# 🧪 Preparing GuardDuty-SOAR for Testing

This project employs a multi-layered testing strategy to ensure code quality, correctness, and reliability. The test suite is managed by <mark style="color:$primary;">`pytest`</mark> and leverages <mark style="color:$primary;">`uv`</mark> for environment and dependency management.

#### Test Categories

The test suite is divided into three distinct categories, which can be run independently.

<table><thead><tr><th width="172">Test Type</th><th>Description</th></tr></thead><tbody><tr><td>Unit</td><td>Fast, isolated tests that validate a single component (e.g., an Action or helper function) in memory without external dependencies.</td></tr><tr><td>Integration</td><td>Verifies individual Actions against live AWS services in isolated, temporary environments. Requires AWS credentials.</td></tr><tr><td>End-to-End (E2E)</td><td>Simulates a full playbook execution triggered by a mock GuardDuty event, interacting with multiple live AWS services to validate the complete workflow. Requires AWS credentials.</td></tr><tr><td>Validation Scenarios</td><td><p>This directory contains Terraform scripts that provision the necessary AWS infrastructure for live validation scenarios.<br></p><p>These scripts are designed to test a fully deployed GuardDuty-SOAR Lambda function against realistic situations. It is highly recommended to run these scenarios as a final verification step after deploying the application, but before connecting the Lambda function to a live Guard-Duty event stream.</p></td></tr></tbody></table>

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

{% hint style="info" %}
## **Note**:

The <mark style="color:$primary;">`.env`</mark> file is listed in <mark style="color:$primary;">`.gitignore`</mark> and will never be committed to source control, ensuring your credentials remain private.
{% endhint %}

1.  Populate the <mark style="color:$primary;">`.env`</mark> File: Open the newly created <mark style="color:$primary;">`.env`</mark> file and replace the placeholder values with resources from your AWS test account. These environment variables directly correspond to the settings in the production <mark style="color:$primary;">`gd.cfg`</mark> file.

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

<table><thead><tr><th width="178">Test Suite</th><th>Command</th><th>Description</th></tr></thead><tbody><tr><td>Unit Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "not integration and not e2e"</code></mark></td><td>Runs all fast, local tests that do not require AWS credentials.</td></tr><tr><td>Integration Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "integration"</code></mark></td><td>Runs tests for individual Actions against live AWS services.</td></tr><tr><td>E2E Tests</td><td><mark style="color:$primary;"><code>uv run pytest -m "e2e"</code></mark></td><td>Runs full playbook simulations against live AWS services.</td></tr><tr><td>Validation Scenarios</td><td>not ran with UV directions are below.</td><td>Full test scenarios before the application is fully deployed and hooked up.</td></tr></tbody></table>

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

***

#### 4. Validation Scenarios

This is the best way to verify that your Lambda is deployed correctly and has the necessary IAM permissions to execute its playbooks.

This section provides a collection of live-action test scenarios that you can run in your own AWS account. Each scenario uses Terraform to create temporary "victim" resources and provides a sample event to trigger your GuardDuty-SOAR Lambda function.

#### Available Scenarios

* **ec2-instance-compromise-full**
  * **This test runs against a full suite setup, ensuring all capabilities are tested. With multiple EBS volumes attached to the instance and a fully functional instance profile. (You can modify your configurations to test** <mark style="color:$primary;">allow\_terminate</mark> **functionality.)**
* **ec2-instance-compromise-short**
  * **This test runs against a bare EC2 setup. No instance-profile, no volumes attached. It's used to ensure that the missing objects are properly handled by the application.**

#### Example Scenario Setup

**Prerequisites**:

* Terraform installed and configured with AWS credentials.
* The GuardDuty-SOAR Lambda function is deployed in your AWS account.

**Instructions**

1.  Deploy the Test Infrastructure: Navigate to test directory and run Terraform.

    ```bash
    terraform init
    terraform apply --auto-approve
    ```
2. Prepare the Test Event: We utilize Terraform to automatically populate a sample event finding with the newly created items ids. You have two actions you can use with this populated JSON.
   1. **Scenario 1 - Invoke the Lambda using Lambdas test functionality in Console:** Use the provided JSON file, copy the contents and paste the contents into the test payload of the Lambda function. Save the new test with whatever name you like. Then, invoke the test.
   2.  **Scenario 2 - Invoke the Lambda Function using CLI/API**: Use the AWS CLI to manually trigger your deployed Lambda function with the updated <mark style="color:$primary;">`event.auto.json`</mark>.

       ```bash
       aws lambda invoke \
           --function-name Your-GuardDuty-SOAR-FunctionName \
           --payload file://event.auto.json \
           response.json
       ```



3. Verify the Results:
   1. Check the EC2 Console: Navigate to the EC2 service. You should observe that your test instance is now associated with a new security group named `gd-soar-quarantine-...`.
   2. Check Notifications: You should receive a "Playbook Complete" notification via your configured SES or SNS channel.
   3. Check Logs: Review the CloudWatch logs for your Lambda function to see the detailed execution flow.&#x20;
   4. Clean Up: Once you have verified the results, destroy the test infrastructure.
   5. ```bash
      terraform destroy --auto-approve
      ```

{% hint style="warning" %}
## Cleanup Notes and Considerations

Do to the nature of the tests, Terraform cannot clean up what it doesn't know about. Anything that is created as a result of the test, needs to be manually cleaned up in these scenarios. For instance, EC2 Instance Compromise playbook will provision a new security group, and snapshots for each volume. Those particular items would need to be manually cleaned.
{% endhint %}
