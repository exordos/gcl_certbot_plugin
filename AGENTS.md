# RestAlchemy Agent Guide

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```text
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## Project layout

`gcl_certbot_plugin/` is the distributable Python package. The Certbot DNS authenticator lives in `plugin.py`, Genesis Core DNS access in `clients.py`, and direct ACME certificate helpers in `acme.py`. Keep runnable usage examples in `gcl_certbot_plugin/examples/`. Tests belong under `gcl_certbot_plugin/tests/`, currently split into `unit/` and the supported (but not yet populated) `functional/` suite. Packaging, dependencies, Ruff, mypy, and coverage settings are in `pyproject.toml`; tox environments are in `tox.ini`.

## Setup, build, and test

Use Python 3.10 or newer and `uv`/`tox-uv` as the project tooling.

```bash
uv tool install tox --with tox-uv  # install the test runner
tox -e py310                       # run unit tests on Python 3.10
tox -e py310-functional            # run functional tests
tox -e ruff-check                  # check formatting and lint rules
tox -e ruff                        # apply Ruff lint/import/format fixes
tox -e mypy                        # type-check the package
tox                                 # run configured test matrix and coverage report
```

The CI matrix verifies Python 3.10, 3.12, and 3.14. Coverage artifacts are written to `cover/`.

## Build & Dependencies

- **Build System**: `pyproject.toml` (PEP 517/518 compliant)
- **Python Version**: Configured in `pyproject.toml`
- **Dependencies**: Listed in `pyproject.toml` under `[project.dependencies]`

## Testing

- **Test Framework**: pytest (configured in `pyproject.toml`)
- **Test Location**: `tests/` directory
- **Configuration**: `tox.ini` for test environment management

## Development Setup

1. Install dependencies: `pip install -e .`
2. Run tests: `pytest` or `tox`

## Code Style and Naming Conventions

### Style Guidelines

- **Indentation**: 4 spaces (Python standard)
- **Line length**: 88 characters (Ruff default)
- **Imports**: Grouped and sorted via Ruff (I rule)
- **Type hints**: Required for all function signatures

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `BaseResourceController`)
- **Functions/variables**: `snake_case` (e.g., `build_filter`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `PACKAGE_NAME`)
- **Private members**: Leading underscore (e.g., `_internal_method`)
- **Comments for code**: write in English

### Testing Requirements

- **Unit tests**: Located in `restalchemy/tests/unit/`
- **Functional tests**: Located in `restalchemy/tests/functional/`
- **Test naming**: `test_<method_name>_<scenario>`
- **Coverage**: Measured via `coverage.py`, HTML report in `cover/`

## VCS Recommendations

### Commit Message Format

```text
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`  
**Scopes**: `cli`, `builder`, `repo`, `packer`, `tests`

**Example:**

```text
feat(repo): add HTTP server proxy driver

- Implement SimplePythonRepoDriver for file serving
- Add port configuration and error handling
- Include unit tests for driver lifecycle

Closes #123
```

### Pull Request Requirements

- **Title**: Use imperative, present tense: "Add feature", not "Added feature"
- **Description**: Clear summary of changes