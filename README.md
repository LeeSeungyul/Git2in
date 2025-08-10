# Git2in

A self-hosted Git repository manager with HTTP Smart Protocol support, built with Python and FastAPI.

## Features

- Git HTTP Smart Protocol proxy
- Token-based authentication
- Namespace and repository management
- Domain-driven design architecture
- Structured logging with correlation IDs
- Comprehensive error handling
- Prometheus metrics support
- Audit logging

## Quick Start

### Prerequisites

- Python 3.11+
- Git
- Virtual environment (venv)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Git2in
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy environment configuration:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run the development server:
```bash
python run.py
```

The API will be available at `http://localhost:8000`

## API Documentation

- Interactive docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI schema: `http://localhost:8000/openapi.json`

## Project Structure

```
src/
├── api/            # FastAPI routes and endpoints
├── core/           # Domain models and business logic
├── adapters/       # External service integrations
├── ports/          # Interfaces and protocols
├── infrastructure/ # Technical infrastructure
│   ├── logging.py  # Structured logging setup
│   └── middleware/ # HTTP middleware
└── main.py         # Application entry point
```

## Configuration

All configuration is managed through environment variables. See `.env.example` for available options.

Key configurations:
- `ENVIRONMENT`: Set to `development`, `staging`, or `production`
- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)
- `REPOSITORY_BASE_PATH`: Where Git repositories are stored
- `SECRET_KEY`: Used for token signing (change in production!)

## Development

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black src tests
```

### Linting

```bash
pylint src
mypy src
```

### Pre-commit Hooks

```bash
pre-commit install
pre-commit run --all-files
```

## Docker

Build the image:
```bash
docker build -t git2in .
```

Run with Docker Compose:
```bash
docker-compose up
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.