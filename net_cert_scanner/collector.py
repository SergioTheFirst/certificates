"""Remote certificate collection via WMI/DCOM (impacket).

Strategy:
  1. WMIExecutor  — DCOM/WMI Win32_Process.Create, output via temp file on C$.
  2. SmbExecExecutor — DCE/RPC service creation (fallback, noisier).
  3. Both fail → ScanError logged, host skipped.

The PowerShell command is Base64-encoded (-EncodedCommand) to avoid any
shell-escaping issues with special characters in cert subjects/passwords.

Output temp file: C:\\Windows\\Temp\\ncs_<uuid8>.json
Read back via SMB: C$\\Windows\\Temp\\ncs_<uuid8>.json
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import CertInfo, HostInfo, ScanError, ScanResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PowerShell script executed on each remote host (single call).
# Returns JSON: {hostname, mac, certs: [{Thumbprint, Subject, Issuer,
#                                         NotAfter, NotBefore, DaysLeft}]}
# ---------------------------------------------------------------------------
_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$hn = $env:COMPUTERNAME
$mac = try {
    (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
     Sort-Object InterfaceIndex | Select-Object -First 1).MacAddress
} catch {
    try {
        (Get-WmiObject Win32_NetworkAdapterConfiguration |
         Where-Object { $_.IPEnabled -eq $true } |
         Select-Object -First 1).MACAddress
    } catch { 'unknown' }
}
$certs = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Thumbprint = $_.Thumbprint
            Subject    = ($_.Subject -replace '"','')
            Issuer     = ($_.Issuer  -replace '"','')
            NotAfter   = $_.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
            NotBefore  = $_.NotBefore.ToString('yyyy-MM-ddTHH:mm:ss')
            DaysLeft   = [int](($_.NotAfter - (Get-Date)).TotalDays)
        }
    })
@{ hostname=$hn; mac=$mac; certs=$certs } | ConvertTo-Json -Depth 3 -Compress
""".strip()


def _encode_ps(script: str) -> str:
    """Encode a PowerShell script as Base64 UTF-16LE for -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _parse_host_json(ip: str, raw_json: str) -> HostInfo:
    """Parse the JSON returned by the PowerShell script into a HostInfo."""
    data: Dict[str, Any] = json.loads(raw_json)
    certs: List[CertInfo] = []

    raw_certs = data.get("certs") or []
    if isinstance(raw_certs, dict):
        # PowerShell returns a dict (not list) when there is exactly one cert
        raw_certs = [raw_certs]

    for c in raw_certs:
        try:
            not_after = datetime.strptime(c["NotAfter"], "%Y-%m-%dT%H:%M:%S")
            not_before = datetime.strptime(c["NotBefore"], "%Y-%m-%dT%H:%M:%S")
            certs.append(
                CertInfo(
                    thumbprint=c.get("Thumbprint", ""),
                    subject=c.get("Subject", ""),
                    issuer=c.get("Issuer", ""),
                    not_after=not_after,
                    not_before=not_before,
                    days_left=int(c.get("DaysLeft", 0)),
                )
            )
        except (KeyError, ValueError) as exc:
            log.warning("Could not parse cert entry from %s: %s — %s", ip, c, exc)

    return HostInfo(
        ip=ip,
        hostname=data.get("hostname") or ip,
        mac=data.get("mac") or "",
        certs=certs,
    )


# ---------------------------------------------------------------------------
# WMI executor
# ---------------------------------------------------------------------------

class WMIExecutor:
    """Execute a PowerShell script on a remote host via DCOM/WMI.

    Uses Win32_Process.Create to start the process, writes output to a temp
    file on C:\\Windows\\Temp, then reads it back via the C$ admin share.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "",
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.timeout = timeout
        self._smb: Any = None
        self._dcom: Any = None
        self._wbem: Any = None

    def __enter__(self) -> "WMIExecutor":
        self._connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self._disconnect()

    def _connect(self) -> None:
        # Import here so the module loads on non-Windows without crashing
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5.dcomrt import (
                DCOMConnection,
                CLSID_WbemLevel1Login,
                IID_IWbemLevel1Login,
                IWbemLevel1Login,
            )
            from impacket.dcerpc.v5.ndr import NULL
        except ImportError as exc:
            raise ImportError(
                f"impacket DCOM/WMI modules not found (version issue?). "
                f"Update impacket: pip install --upgrade impacket. Error: {exc}"
            ) from exc

        try:
            self._smb = SMBConnection(self.host, self.host, timeout=15)
            self._smb.login(self.username, self.password, self.domain)

            self._dcom = DCOMConnection(
                self.host,
                self.username,
                self.password,
                self.domain,
                "",
                "",
                oxidResolver=True,
                doKerberos=False,
            )
            iface = self._dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            login = IWbemLevel1Login(iface)
            self._wbem = login.NTLMLogin("//./root/cimv2", NULL, NULL)
            login.RemRelease()
        except Exception as exc:
            self._disconnect()
            raise

    def _disconnect(self) -> None:
        if self._dcom:
            try:
                self._dcom.disconnect()
            except Exception:
                pass
        if self._smb:
            try:
                self._smb.logoff()
            except Exception:
                pass

    def execute_ps(self, script: str) -> str:
        """Run a PowerShell script and return its stdout as a string.

        Raises TimeoutError if the output file is not written within self.timeout.
        """
        out_name = f"ncs_{uuid.uuid4().hex[:8]}.json"
        out_remote = f"C:\\Windows\\Temp\\{out_name}"
        out_smb = f"Windows\\Temp\\{out_name}"

        encoded = _encode_ps(script)
        cmd = (
            f"cmd.exe /Q /c powershell.exe -NoProfile -NonInteractive "
            f"-ExecutionPolicy Bypass -EncodedCommand {encoded} "
            f"> {out_remote} 2>&1"
        )

        win32_process, _ = self._wbem.GetObject("Win32_Process")
        win32_process.Create(cmd, "C:\\", None)

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                chunks: List[bytes] = []
                self._smb.getFile("C$", out_smb, chunks.append)
                output = b"".join(chunks).decode("utf-8-sig", errors="replace").strip()
                try:
                    self._smb.deleteFiles("C$", out_smb)
                except Exception:
                    pass
                return output
            except Exception:
                time.sleep(0.5)

        raise TimeoutError(
            f"Timeout ({self.timeout}s) waiting for remote output on {self.host}"
        )


# ---------------------------------------------------------------------------
# SmbExec fallback executor (via DCE/RPC service creation)
# ---------------------------------------------------------------------------

class SmbExecExecutor:
    """Fallback: create a temporary Windows service via SMB DCE/RPC.

    Similar to PsExec but implemented entirely through impacket.
    Noisier than WMI (creates a service entry in the Windows service manager).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "",
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.timeout = timeout
        self._smb: Any = None

    def __enter__(self) -> "SmbExecExecutor":
        from impacket.smbconnection import SMBConnection

        self._smb = SMBConnection(self.host, self.host, timeout=15)
        self._smb.login(self.username, self.password, self.domain)
        return self

    def __exit__(self, *_: Any) -> None:
        if self._smb:
            try:
                self._smb.logoff()
            except Exception:
                pass

    def execute_ps(self, script: str) -> str:
        """Run a PowerShell script via a temporary Windows service."""
        try:
            from impacket.dcerpc.v5 import transport, scmr
        except ImportError as exc:
            raise ImportError(
                f"impacket scmr module not found (version issue?). "
                f"Update impacket: pip install --upgrade impacket. Error: {exc}"
            ) from exc
        from impacket.dcerpc.v5.ndr import NULL

        out_name = f"ncs_{uuid.uuid4().hex[:8]}.json"
        out_remote = f"C:\\Windows\\Temp\\{out_name}"
        out_smb = f"Windows\\Temp\\{out_name}"
        svc_name = f"ncs{uuid.uuid4().hex[:6]}"

        encoded = _encode_ps(script)
        bin_path = (
            f"cmd.exe /Q /c powershell.exe -NoProfile -NonInteractive "
            f"-ExecutionPolicy Bypass -EncodedCommand {encoded} "
            f"> {out_remote} 2>&1"
        )

        string_binding = f"ncacn_np:{self.host}[\\pipe\\scmr]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(
            self.username, self.password, self.domain, "", "", None
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        try:
            scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            svc = scmr.hRCreateServiceW(
                dce,
                scm,
                svc_name,
                svc_name,
                lpBinaryPathName=bin_path,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )["lpServiceHandle"]

            try:
                scmr.hRStartServiceW(dce, svc)
            except Exception:
                pass  # Service may "fail" but still run the command

            time.sleep(2)

            try:
                scmr.hRDeleteService(dce, svc)
                scmr.hRCloseServiceHandle(dce, svc)
            except Exception:
                pass

            scmr.hRCloseServiceHandle(dce, scm)
        finally:
            dce.disconnect()

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                chunks: List[bytes] = []
                self._smb.getFile("C$", out_smb, chunks.append)
                output = b"".join(chunks).decode("utf-8-sig", errors="replace").strip()
                try:
                    self._smb.deleteFiles("C$", out_smb)
                except Exception:
                    pass
                return output
            except Exception:
                time.sleep(0.5)

        raise TimeoutError(
            f"Timeout ({self.timeout}s) waiting for smbexec output on {self.host}"
        )


# ---------------------------------------------------------------------------
# Public collection function
# ---------------------------------------------------------------------------

def _collect_one(
    ip: str,
    username: str,
    password: str,
    domain: str,
    timeout: int,
) -> HostInfo | ScanError:
    """Try WMI, then SmbExec. Return HostInfo on success, ScanError on failure."""
    executors = [
        ("wmiexec", WMIExecutor),
        ("smbexec", SmbExecExecutor),
    ]
    last_error = ""
    last_method = ""

    for method_name, ExecutorClass in executors:
        last_method = method_name
        try:
            with ExecutorClass(ip, username, password, domain, timeout) as exe:
                raw = exe.execute_ps(_PS_SCRIPT)

            if not raw:
                raise ValueError("Empty response from remote host")

            # Strip any leading garbage before the JSON object
            json_start = raw.find("{")
            if json_start > 0:
                raw = raw[json_start:]

            host = _parse_host_json(ip, raw)
            log.info(
                "[%s] %s (%s) — %d cert(s) via %s",
                ip,
                host.hostname,
                host.mac,
                len(host.certs),
                method_name,
            )
            return host

        except Exception as exc:
            last_error = str(exc)
            # Log at INFO for first attempt (WMI), DEBUG for fallbacks
            if method_name == "wmiexec":
                log.info("[%s] %s failed: %s", ip, method_name, exc)
            else:
                log.debug("[%s] %s failed: %s", ip, method_name, exc)

    log.warning("[%s] All methods failed. Last error (%s): %s", ip, last_method, last_error)
    return ScanError(ip=ip, method=last_method, reason=last_error)


def collect_all(
    live_ips: List[str],
    username: str,
    password: str,
    domain: str = "",
    max_workers: int = 15,
    timeout: int = 30,
) -> ScanResult:
    """Collect certificates from all live hosts in parallel.

    Args:
        live_ips: List of IP addresses with port 445 open.
        username: Admin account username (optionally with domain prefix).
        password: Admin account password.
        domain: Windows domain name (empty for local accounts).
        max_workers: Thread pool size.
        timeout: Per-host command timeout (seconds).

    Returns:
        ScanResult with populated hosts and errors.
    """
    result = ScanResult(timestamp=datetime.now())

    # Split "DOMAIN\\user" into domain + user if needed
    if "\\" in username and not domain:
        domain, username = username.split("\\", 1)

    log.info(
        "Collecting certificates from %d host(s) with %d workers",
        len(live_ips),
        max_workers,
    )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_collect_one, ip, username, password, domain, timeout): ip
            for ip in live_ips
        }
        for future in as_completed(future_map):
            outcome = future.result()
            if isinstance(outcome, HostInfo):
                result.hosts.append(outcome)
            else:
                result.errors.append(outcome)

    log.info(
        "Collection done: %d successful, %d failed",
        result.successful,
        result.failed,
    )
    return result
