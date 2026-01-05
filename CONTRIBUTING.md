# Contributing

Thank you for your interest in making RAG pipelines safer!

## 1. Development Setup

We use [uv](https://github.com/astral-sh/uv) for dependency management. It is extremely fast and manages Python versions automatically.

### Prerequisites
* Install `uv`:
    ```bash
    # On macOS/Linux
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # On Windows
    powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

### Installation
1.  Clone the repository:
    ```bash
    git clone https://github.com/daved01/deconvolute.git
    cd deconvolute
    ```

2.  Create the environment and install all dependencies (including dev tools, ML, and YARA):
    ```bash
    uv sync --all-extras
    ```

3.  Activate the environment:
    ```bash
    # macOS/Linux
    source .venv/bin/activate

    # Windows
    .venv\Scripts\activate
    ```

4.  Verify installation:
    ```bash
    # Should run without errors
    pytest --version
    python -c "import deconvolute; print(deconvolute.__version__)"
    ```

## 2. Development
TODO

### Running Tests & Linting
We enforce high code quality using **Ruff** (linting/formatting) and **Mypy** (static typing). 

These checks run in CI, so please run them locally before pushing. You can run tools directly via `uv run` (no activation needed) or inside the activated shell.


#### 1. Run the Linters (Ruff)
Ruff checks for bugs, security issues, and formatting violations.

```bash
# Check for errors (Read-only)
uv run ruff check .

# Auto-fix simple errors and format code
uv run ruff check --fix .
uv run ruff format .
```

#### 2. Run Type Checking (Mypy)

Mypy ensures you aren't passing the wrong types to functions.

```bash
uv run mypy .
```

#### 3. Run Tests (Pytest)

```bash
# Run all tests
uv run pytest

# Run tests with coverage report
uv run pytest --cov=deconvolute
```

### Commit Messages
We follow Conventional Commits. This allows us to generate changelogs automatically.

- `feat`: add new YARA scanner (Adds functionality)
- `fix`: handle empty PDF inputs (Fixes a bug)
- `docs`: update README quickstart (Documentation only)
- `chore`: update dependencies (Maintenance)
- `test`: add regression vectors (Tests only)


### Release Process (Maintainers Only)

1.  **Generate Changelog:**
    Run the following command locally to generate the changelog for the new version (e.g. `0.1.0`):

    ```bash
    uv run git-cliff --tag 0.1.0 --output CHANGELOG.md
    ```
2.  **Bump Version:** Update `__version__` string in `src/deconvolute/__init__.py`.
3.  **Commit & Push:**
    Commit the `CHANGELOG.md` and `__init__.py` files, then push to `main`.
    ```bash
    git commit -am "chore(release): prepare v0.1.0"
    git push origin main
    ```
4.  **Trigger Release:**
    * Go to the **Actions** tab on GitHub.
    * Select **Release to TestPyPI** (or **Release to PyPI** once configured).
    * Click **Run workflow** and enter the version number (e.g. `0.1.0`).

## 3. TODO: More coming soon

