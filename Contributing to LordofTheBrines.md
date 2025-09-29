# Contributing to ![LordofTheBrines](LordoftheBrines.png)

Thank you for your interest in contributing to LordofTheBrines! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

## How to Contribute

### Reporting Bugs

If you find a bug in LordofTheBrines, please report it by creating an issue in the GitHub repository. When reporting a bug, please include:

1. A clear and descriptive title
2. Steps to reproduce the bug
3. Expected behavior
4. Actual behavior
5. Environment information (OS, Python version, etc.)
6. Any relevant logs or error messages

### Suggesting Enhancements

If you have an idea for an enhancement or new feature, please create an issue in the GitHub repository. When suggesting an enhancement, please include:

1. A clear and descriptive title
2. A detailed description of the enhancement
3. Any relevant examples or use cases
4. If applicable, any references to similar features in other projects

### Pull Requests

We welcome pull requests! To submit a pull request:

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Submit a pull request

Please ensure your pull request:

- Follows the coding style of the project
- Includes tests for new functionality
- Updates documentation as needed
- Has a clear and descriptive title
- Includes a description of the changes

## Development Setup

To set up a development environment for LordofTheBrines:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/lordofthebrines.git
   cd lordofthebrines
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Run tests:
   ```bash
   pytest
   ```

## Coding Style

LordofTheBrines follows the [Black](https://github.com/psf/black) code style. Please ensure your code is formatted with Black before submitting a pull request.

```bash
black lordofthebrines tests
```

We also use [isort](https://github.com/PyCQA/isort) for import sorting:

```bash
isort lordofthebrines tests
```

And [flake8](https://github.com/PyCQA/flake8) for linting:

```bash
flake8 lordofthebrines tests
```

## Testing

All new code should include tests. We use [pytest](https://docs.pytest.org/) for testing.

To run tests:

```bash
pytest
```

To run tests with coverage:

```bash
pytest --cov=lordofthebrines
```

## Documentation

All new code should include documentation. We use [Google-style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for Python code.

## Versioning

LordofTheBrines follows [Semantic Versioning](https://semver.org/). Version numbers are in the format MAJOR.MINOR.PATCH:

- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backwards-compatible manner
- PATCH version for backwards-compatible bug fixes

## License

By contributing to LordofTheBrines, you agree that your contributions will be licensed under the project's GNU General Public License v3.0.

## Questions

If you have any questions about contributing, please create an issue in the GitHub repository or contact the maintainers directly.

Thank you for contributing to LordofTheBrines!
