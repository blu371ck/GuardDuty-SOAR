# Testing Setup

This workflow is for developers who want to contribute to the codebase, run tests, and manage dependencies.

1. Clone the repository and move into the directory

```bash
git clone https://github.com/blu371ck/GuardDuty-SOAR.git
cd GuardDuty-SOAR
```

2. Create a virtual env:

```
uv venv
```

3. Setting up the Development Environment Install all production and development dependencies from the lock file. This ensures your environment is identical to the one used in CI.

```bash
# Install all dependencies
uv pip sync -r requirements-dev.txt

# Install the guardduty-soar package itself in "editable" mode
uv pip install -e .
```

#### Dependency Management:

Do not manually edit the requirements.txt files. All dependencies are managed in pyproject.toml.

* Add the new package to the appropriate list in pyproject.toml.
* Re-compile the lock files:

```bash
# Update production requirements
uv pip compile pyproject.toml -o requirements.txt

# Update development requirements
uv pip compile pyproject.toml --extra dev -o requirements-dev.txt
```

Sync your local environment:

```bash
uv pip sync -r requirements-dev.txt
```

Commit the changes to pyproject.toml and both requirements files.

### Running Tests&#x20;

There are three types of tests in this application, unit tests, integration tests and e2e (end-to-end) tests.

#### Unit Tests

The unit tests are simple, utilizing mocking to test functionality in isolation without requiring any actual infrastructure.

To run unit tests, run:

```bash
uv run pytest -m "not integration and not e2e"
```

To add new unit tests, simply follow the structure and insert them into the <mark style="color:$primary;">`/tests`</mark> directory. Ensure you do not put any unit tests inside the <mark style="color:$primary;">`integration/`</mark> or <mark style="color:$primary;">`e2e/`</mark> folders, as those are dedicated specifically for those kinds of tests.

#### Integration testing

**Integration Tests** interact with real AWS resources and require valid AWS credentials. They also require you to configure a <mark style="color:$primary;">`gd.test.cfg`</mark> file. For integration the only item we truly require is that you provide a testing subnet, named <mark style="color:$primary;">`testing-subnet`</mark>. As the tests grow and encompass more services, these requirements may change and increase.

To create a testing configuration:

1. Copy the example config: <mark style="color:$primary;">`cp gd.test.cfg.example gd.test.cfg`</mark>
2. Edit <mark style="color:$primary;">`gd.test.cfg`</mark> and fill in the values for your AWS test account.
3. Run the integration tests:

To run integration tests run

```bash
uv run pytest -m "integration"
```

**Since integration tests spin up real AWS resources, and we tear them down at the end. These tests can take some time to complete.**

#### **End-to-end (E2E) Tests**

**E2E Tests** are created for each playbook. Going through every action and step to ensure it works in the cloud. They are appropriately named after the playbook they test and can be ran in bulk with:

```bash
uv run pytest -m "e2e"
```

E2E tests also spin up AWS infrastructure to test out the entire playbook. So, each E2E test has setup and teardown just like integration tests. They do take some time.

### Development Verbosity

When running any tests, if you would like to see more logging and information about what is going on run:

```bash
uv run pytest -s -m <test-specific-command-here>
```
