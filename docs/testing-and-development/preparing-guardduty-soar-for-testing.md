# 🧪 Preparing GuardDuty-SOAR for Testing

This project employs a multi-layered testing strategy to ensure code quality, correctness, and reliability. The test suite is managed by <mark style="color:$primary;">`pytest`</mark> and leverages <mark style="color:$primary;">`uv`</mark> for environment and dependency management.

#### Test Categories

The test suite is divided into three distinct categories, which can be run independently.

<table><thead><tr><th width="172">Test Type</th><th>Description</th></tr></thead><tbody><tr><td>Unit</td><td>Fast, isolated tests that validate a single component (e.g., an Action or helper function) in memory without external dependencies.</td></tr><tr><td>Integration</td><td>Verifies individual Actions against live AWS services in isolated, temporary environments. Requires AWS credentials.</td></tr><tr><td>End-to-End (E2E)</td><td>Simulates a full playbook execution triggered by a mock GuardDuty event, interacting with multiple live AWS services to validate the complete workflow. Requires AWS credentials.</td></tr></tbody></table>

Export to Sheets

***

#### 1. Initial Setup

Before executing the tests, you must set up your local environment and configure the necessary parameters for tests that interact with AWS. All commands should be run from the root of the project directory.

**Environment and Dependencies**

1.  Create a Virtual Environment:

    ```bash
    uv venv
    ```
2.  Activate the Virtual Environment:

    ```bash
    # On Windows (PowerShell)
    .venv\Scripts\Activate.ps1

    # On macOS/Linux
    source .venv/bin/activate
    ```
3.  Install All Dependencies: The `sync` command installs all production (<mark style="color:$primary;">`requirements.txt`</mark>) and development (<mark style="color:$primary;">`requirements-dev.txt`</mark>) dependencies, ensuring your environment matches the project's lockfiles.

    ```bash
    uv pip sync requirements.txt requirements-dev.txt
    ```

**Test Configuration (**<mark style="color:$primary;">**`.env`**</mark>**&#x20;file)**

The integration and E2E tests require AWS credentials and resource identifiers. These are managed via a local <mark style="color:$primary;">`.env`</mark> file.

1.  Create a <mark style="color:$primary;">`.env`</mark> file: Copy the provided example file to create your local configuration.

    ```bash
    # On Windows
    copy .env.example .env

    # On macOS/Linux
    cp .env.example .env
    ```

    > **Note**: The <mark style="color:$primary;">`.env`</mark> file is listed in <mark style="color:$primary;">`.gitignore`</mark> and will never be committed to source control, ensuring your credentials remain private.
2.  Populate the <mark style="color:$primary;">`.env`</mark> File: Open the newly created <mark style="color:$primary;">`.env`</mark> file and replace the placeholder values with resources from your AWS test account. These environment variables directly correspond to the settings in the production <mark style="color:$primary;">`gd.cfg`</mark> file.

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

***

#### 2. Running the Tests

Simple shortcuts are provided via <mark style="color:$primary;">`uv run`</mark> to execute different categories of tests using <mark style="color:$primary;">`pytest`</mark> markers.

<table><thead><tr><th width="178">Test Suite</th><th>Command</th><th>Description</th></tr></thead><tbody><tr><td>Unit Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "not integration and not e2e"</code></mark></td><td>Runs all fast, local tests that do not require AWS credentials.</td></tr><tr><td>Integration Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "integration"</code></mark></td><td>Runs tests for individual Actions against live AWS services.</td></tr><tr><td>E2E Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "e2e"</code></mark></td><td>Runs full playbook simulations against live AWS services.</td></tr></tbody></table>

***

#### 3. Advanced Test Execution

For development and debugging, you can target specific tests or modify the output.

**Running a Single File**

To run all tests within a specific file:

```bash
uv run pytest tests/e2e/ec2/test_e2e_ec2_instance_compromise.py
```

**Running a Single Test by Name**

Use the <mark style="color:$primary;">`-k`</mark> flag to run tests whose names match a specific expression:

```bash
uv run pytest -k "test_remove_public_access_integration"
```

**Displaying Live Logs**

Add the <mark style="color:$primary;">`-s`</mark> flag to any <mark style="color:$primary;">`pytest`</mark> command to display <mark style="color:$primary;">`print`</mark> statements and log output from the application and tests in real-time.

```bash
uv run pytest -s -m "e2e"
```
