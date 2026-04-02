.PHONY: install test lint run clean

install:
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v --tb=short --cov=net_cert_scanner --cov-report=term-missing

lint:
	flake8 net_cert_scanner/ tests/ --max-line-length=100
	mypy net_cert_scanner/ --ignore-missing-imports

run:
	python -m net_cert_scanner

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache htmlcov .coverage
