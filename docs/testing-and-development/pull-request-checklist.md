---
icon: arrow-progress
---

# Pull Request Checklist

To maintain a high standard of code quality, consistency, and stability, all contributors are required to complete the following checks before submitting a pull request. Ensuring these steps are completed helps prevent common issues and significantly speeds up the code review process.

All commands should be run from the root of the project directory.

***

#### Pre-Submission Quality Assurance

Before your pull request is ready for review, please complete the following four steps.

**1. Sort Imports with&#x20;**<mark style="color:$primary;">**`isort`**</mark>

Ensure all Python imports are sorted correctly and consistently across the codebase. Run <mark style="color:$primary;">`isort`</mark> against both the source and test directories.

```bash
uv run isort src tests
```

**2. Format Code with&#x20;**<mark style="color:$primary;">**`black`**</mark>

Format the entire codebase according to the <mark style="color:$primary;">`black`</mark> code style. This ensures a uniform and readable style across the project.

```bash
uv run black src tests
```

**3. Perform Static Type Checking with&#x20;**<mark style="color:$primary;">**`mypy`**</mark>

Run static type analysis on the application's source code to catch potential type-related errors before runtime. The <mark style="color:$primary;">`mypy`</mark> check must pass without any errors.

```
uv run mypy src
```

**4. Execute the Full Test Suite with&#x20;**<mark style="color:$primary;">**`pytest`**</mark>

Run the complete test suite to confirm that your changes have not introduced any regressions and that all functionality works as expected. All tests (Unit, Integration, and E2E) must pass.

You can run the entire suite with a single command:

```bash
uv run pytest
```

For reference, the individual test categories can be run with the following commands:

*   Unit Tests:

    ```bash
    uv run pytest -m "not integration and not e2e"
    ```
*   Integration Tests (Requires AWS Credentials):

    ```bash
    uv run pytest -m "integration"
    ```
*   E2E Tests (Requires AWS Credentials):

    ```bash
    uv run pytest -m "e2e"
    ```

***

Once all checks pass without any errors, your pull request is ready for review. Thank you for your contribution!
