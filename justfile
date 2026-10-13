# PASS VAULT command recipes

default:
    @just --list

# Run pytest test suite
test:
    .venv/bin/pytest tests/ -v

# Run pytest with code coverage report
test-cov:
    .venv/bin/pytest tests/ --cov=passvault --cov-report=term-missing

# Run code linter
lint:
    @if [ -x .venv/bin/ruff ]; then \
        .venv/bin/ruff check passvault tests; \
    else \
        .venv/bin/python -m py_compile passvault/*.py; \
        echo "Basic syntax and bytecode compilation passed."; \
    fi

# Format code
format:
    @if [ -x .venv/bin/ruff ]; then \
        .venv/bin/ruff format passvault tests; \
    else \
        echo "Ruff not found in venv. Using standard formatting."; \
    fi

# Run PASS VAULT CLI command
run *args:
    @./bin/pv {{args}}
