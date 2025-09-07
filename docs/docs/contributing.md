# Contributing to pyMC_Core

We welcome contributions to pyMC_Core! This document provides guidelines for contributing to the project.

## Development Setup

!!! warning "Virtual Environment Required"
    Due to Python 3.11+'s externally-managed-environment restrictions, you **must** use a virtual environment when working with pyMC Core. This prevents conflicts with system packages and ensures a clean development environment.

1. **Clone the repository**
   ```bash
   git clone https://github.com/rightup/pyMC_core/dev
   cd pyMC_Core
   ```

2. **Set up development environment**
   ```bash
   # Create virtual environment
   python -m venv venv

   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate

   # Install development dependencies
   pip install -e ".[dev]"
   ```

3. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Code Style

We use the following tools for code quality:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

### Pre-commit Hook Configuration

Our pre-commit setup enforces modern Python standards across the entire codebase:

- **File hygiene**: Trailing whitespace removal, end-of-file fixes
- **Python formatting**: Black formatting applied to all Python files
- **Import sorting**: isort applied to all Python files
- **Code linting**: flake8 with standard Python style guidelines
- **Testing**: Automated pytest execution on relevant changes

This ensures consistent code quality and prevents issues from being committed.

Run all checks with:
```bash
pre-commit run --all-files
```

## Testing

- Write unit tests for new features
- Maintain test coverage above 80%
- Run tests with: `pytest`

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and checks**
   ```bash
   pytest
   pre-commit run --all-files
   ```

4. **Update documentation**
   - Update docstrings for public APIs
   - Add examples for new features
   - Update the changelog

5. **Submit a pull request**
   - Provide a clear description of changes
   - Reference any related issues
   - Ensure CI checks pass

## Architecture Guidelines

### Code Quality Standards

We maintain high code quality standards across the entire codebase:

- **PEP 8 compliance**: All code follows Python style guidelines
- **Type hints**: Use type annotations for better code clarity
- **Comprehensive testing**: All features must have corresponding tests
- **Documentation**: Public APIs must have clear docstrings
- **No unused imports**: Clean import statements throughout

### Code Organization

- Keep modules focused and single-purpose
- Use clear, descriptive names

### Async/Await

- Use async/await for I/O operations
- Avoid blocking calls in async functions
- Handle exceptions properly in async contexts

### Error Handling

- Use custom exceptions for domain-specific errors
- Provide meaningful error messages
- Log errors appropriately

### Security

- Never log sensitive information
- Validate all inputs
- Use secure defaults for cryptographic operations

## Documentation

- Use Google-style docstrings
- Document all public APIs
- Provide usage examples
- Keep README and docs up to date

### Building Documentation Locally

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build
```

The documentation will be available at `http://localhost:8000`.

## Hardware Support

When adding support for new hardware:

1. Create a new hardware module in `src/pymc_core/hardware/`
2. Implement the `RadioDevice` interface
3. Add configuration options
4. Include setup instructions

## Protocol Extensions

When extending the protocol:

1. Define new packet types in `constants.py`
2. Implement packet builders and parsers
3. Add validation logic
4. Update the protocol documentation
5. Ensure backward compatibility

## Release Process

- Use semantic versioning (MAJOR.MINOR.PATCH)
- Update CHANGELOG.md for each release
- Tag releases in git
- Publish to PyPI

## Getting Help

- Check existing issues and discussions
- Ask questions in GitHub Discussions
- Join our community chat

Thank you for contributing to pyMC_Core!
