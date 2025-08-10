.PHONY: help install test lint format run-dev clean cli-install cli-test cli-completions

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linters"
	@echo "  make format     - Format code"
	@echo "  make run-dev    - Run development server"
	@echo "  make clean      - Clean up generated files"
	@echo ""
	@echo "CLI commands:"
	@echo "  make cli-install     - Install CLI tool"
	@echo "  make cli-test        - Test CLI commands"
	@echo "  make cli-completions - Generate shell completions"

install:
	pip install --upgrade pip
	pip install -r requirements.txt

test:
	pytest tests/ -v --cov=src --cov-report=term-missing

lint:
	pylint src/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

run-dev:
	python run.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage

cli-install:
	pip install -e .
	@echo "Git2in CLI installed. Run 'git2in --help' to get started."

cli-test:
	@echo "Testing CLI commands..."
	./git2in --version
	./git2in --help
	./git2in config list
	@echo "CLI tests completed successfully."

cli-completions:
	@echo "Generating shell completions..."
	@mkdir -p completions
	@python -c "from src.cli.main import app; import typer; print(typer.completion.get_completion(app, 'bash'))" > completions/git2in.bash
	@python -c "from src.cli.main import app; import typer; print(typer.completion.get_completion(app, 'zsh'))" > completions/git2in.zsh
	@python -c "from src.cli.main import app; import typer; print(typer.completion.get_completion(app, 'fish'))" > completions/git2in.fish
	@echo "Completions generated in completions/ directory"
	@echo "To install:"
	@echo "  Bash: source completions/git2in.bash"
	@echo "  Zsh:  source completions/git2in.zsh"
	@echo "  Fish: cp completions/git2in.fish ~/.config/fish/completions/"