
# Pull Request Checklist

To maintain a high standard of code quality, consistency, and stability, all contributors are required to complete the following checks before submitting a pull request. Ensuring these steps are completed helps prevent common issues and significantly speeds up the code review process.

All commands should be run from the root of the project directory.

## Pre-Submission Quality Assurance
Before your pull request is ready for review, please complete the following six steps. 

**1. Sort Imports with** `isort`

Ensure all Python imports are sorted correctly and consistently across the codebase. Run isort against both the source and test directories. 
```bash
uv run isort src tests
```
**2. Format Code with** `black`

Format the entire codebase according to the black code style. This ensures a uniform and readable style across the project. 
```bash
uv run black src tests
```
**3. Scan for Vulnerabilities with** `bandit`

Run a security-focused static analysis on the source code to find common security vulnerabilities. The bandit scan must pass without any high-severity issues.

```bash
uv run bandit -r src
```
**4. Check for Insecure Dependencies with** `safety`

Scan the project's dependencies to ensure there are no known security vulnerabilities in the third-party packages being used.

```bash
uv run safety check
```
**5. Perform Static Type Checking with** `mypy`

Run static type analysis on the application's source code to catch potential type-related errors before runtime. The mypy check must pass without any errors. 
```bash
uv run mypy src
```
**6. Execute the Full Test Suite with** `pytest`

Run the complete test suite to confirm that your changes have not introduced any regressions and that all functionality works as expected. All tests (Unit, Integration, and E2E) must pass. 

You can run the entire suite with a single command: 
```bash
uv run pytest
```
For reference, the individual test categories can be run with the following commands: 
- **Unit Tests**: 
```Bash
uv run pytest -m "not integration and not e2e"
```
- **Integration Tests (Requires AWS Credentials)**: 
```Bash
uv run pytest -m "integration"
```
- **E2E Tests (Requires AWS Credentials)**: 
```Bash
uv run pytest -m "e2e"
```
Once all checks pass without any errors, your pull request is ready for review. Thank you for your contribution!