# Testing Setup

## Testing Guide

This project uses a comprehensive testing strategy divided into three categories: **unit**, **integration**, and **end-to-end (E2E)** tests. We use <mark style="color:$primary;">`pytest`</mark> as our test runner and <mark style="color:$primary;">`uv`</mark> for managing our virtual environment and dependencies.

* **Unit Tests**: Fast, isolated tests that check a single piece of code (like an Action or a helper function) without any external dependencies.
* **Integration Tests**: Tests that verify a single Action against a live AWS service in an isolated, temporary environment. These require AWS credentials. (Can take some time, it is recommended to target specific changed files or new files to reduce time.)
* **E2E Tests**: The most comprehensive tests. They simulate a full playbook run from a mock GuardDuty event to the final outcome, interacting with multiple live AWS services.

### 1. Initial Setup

Before you can run the tests, you need to set up your environment and provide configuration for the tests that interact with AWS.

#### Environment and Dependencies

All commands should be run from the root of the project directory.

1.  Create a virtual environment using <mark style="color:$primary;">`uv`</mark>:

    ```bash
    uv venv
    ```
2. Activate the virtual environment:
   *   On Windows (PowerShell):

       ```powershell
       .venv\Scripts\Activate.ps1
       ```
   *   On macOS/Linux:

       ```bash
       source .venv/bin/activate
       ```
3.  Install all required packages: This command installs both production and development dependencies.

    ```bash
    uv pip sync requirements.txt requirements-dev.txt
    ```

#### Test Configuration (<mark style="color:$primary;">`.env`</mark> file)

The integration and E2E tests require credentials and specific AWS resource ARNs to run. These are managed via a <mark style="color:$primary;">`.env`</mark> file.

1.  Copy the example file: In the project root, copy the <mark style="color:$primary;">`.env.example`</mark> file to a new file named <mark style="color:$primary;">`.env`</mark>.

    ```bash
    # On Windows
    copy .env.example .env

    # On macOS/Linux
    cp .env.example .env
    ```

    > Note: The <mark style="color:$primary;">`.env`</mark> file is listed in <mark style="color:$primary;">`.gitignore`</mark> and will never be committed to source control.
2.  Fill in your values: Open the new <mark style="color:$primary;">`.env`</mark> file and replace the placeholder values with resources from your personal AWS test account. The file will look like this:

    ```bash
    # Environment variables for running GuardDuty SOAR tests

    GD_AWS_REGION="us-east-1"
    GD_LOG_LEVEL="DEBUG"
    GD_BOTO_LOG_LEVEL="WARNING" # Change to DEBUG for verbose AWS logs

    # Notifications
    GD_ALLOW_SES="true"
    GD_REGISTERED_EMAIL_ADDRESS="your-verified-email@example.com"
    GD_ALLOW_SNS="true"
    GD_SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:YourTestTopic"

    # EC2 Actions
    GD_QUARANTINE_SG_ID="sg-xxxxxxxxxxxxxxxxx"
    GD_IAM_DENY_ALL_POLICY_ARN="arn:aws:iam::123456789012:policy/YourDenyPolicy"
    GD_ALLOW_TERMINATE="true"
    GD_ALLOW_REMOVE_PUBLIC_ACCESS="true"
    ```

> Note: A mapping of all testing environment configurations to production configurations is provided in the accompanying sections.

### 2. Running the Tests

We use <mark style="color:$primary;">`uv`</mark> as a task runner to provide simple shortcuts for running different test categories.

#### Running Unit Tests

These are fast and run locally without needing AWS credentials.

```bash
uv run pytest -m "not integration and not e2e"
```

#### Running Integration Tests

These tests interact with live AWS services and require your <mark style="color:$primary;">`.env`</mark> file to be correctly configured and your terminal to have active AWS credentials.

```bash
uv run pytest -m "integration"
```

#### Running End-to-End (E2E) Tests

These are the most comprehensive tests, simulating a full playbook. They also require a configured <mark style="color:$primary;">`.env`</mark> file and active AWS credentials.

```bash
uv run pytest -m "e2e"
```

### 3. Advanced Test Execution

For debugging, you may want to run a specific test file or function. You can do this by calling <mark style="color:$primary;">`pytest`</mark> directly.

*   To run a single file:

    ```bash
    uv run pytest tests/e2e/ec2/test_e2e_ec2_instance_compromise.py
    ```
*   To run a single test by name (using the <mark style="color:$primary;">`-k`</mark> flag):

    ```bash
    uv run pytest -k "test_remove_public_access_integration"
    ```
*   To see <mark style="color:$primary;">log</mark> statements from tests and application code: Add the <mark style="color:$primary;">`-s`</mark> flag to any <mark style="color:$primary;">`pytest`</mark> command.

    ```bash
    uv run pytest -s -m "e2e"
    ```
