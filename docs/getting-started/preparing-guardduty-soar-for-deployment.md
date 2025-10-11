# 🚀 Preparing GuardDuty-SOAR for Deployment

### &#x20;Preparing GuardDuty-SOAR for Deployment

This guide provides comprehensive instructions for deploying the GuardDuty-SOAR application as an AWS Lambda function for production use. For details on local development and testing procedures, please refer to the dedicated testing and development documentation.

#### Prerequisites

Before proceeding with the deployment, ensure the following requirements are met.

* Local Environment:
  * Python 3.13 or newer.
  * `uv` for environment and package management.
* AWS Environment:
  * An active AWS account with programmatic access (credentials configured locally).
  * AWS GuardDuty enabled in the target region(s).

#### Installation and Setup

First, clone the repository and create an isolated virtual environment.

1.  Clone the Repository:

    ```bash
    git clone https://github.com/your-username/guardduty-soar.git
    cd guardduty-soar
    ```
2.  Create a Virtual Environment:

    ```bash
    uv venv
    ```

***

#### Production Deployment

The primary objective for a production deployment is to create a lean <mark style="color:$primary;">`.zip`</mark> artifact containing the application source code and its production dependencies, optimized for the AWS Lambda runtime.

**Building the Lambda Deployment Package**

This process isolates production dependencies and packages them with your source code into a single deployment artifact.

1.  Create a Build Directory: This directory will stage the files for the deployment package.

    ```bash
    mkdir -p build/dist
    ```
2.  Install Production Dependencies: Using the <mark style="color:$primary;">`requirements.txt`</mark> lockfile ensures that the exact, tested versions of all dependencies are installed. The <mark style="color:$primary;">`--target`</mark> flag directs <mark style="color:$primary;">`uv`</mark> to install the packages into a specific directory.

    ```bash
    uv pip install -r requirements.txt --target build/dist/package
    ```
3.  Copy Application Source Code: Copy the <mark style="color:$primary;">`guardduty_soar`</mark> application package from the <mark style="color:$primary;">`src`</mark> directory into the staging directory alongside the dependencies.

    ```bash
    cp -r src/guardduty_soar build/dist/package/
    ```
4.  Create the Deployment Package: Navigate into the staging directory and create a <mark style="color:$primary;">`.zip`</mark> file containing all its contents.

    ```bash
    cd build/dist/package
    zip -r ../lambda_deployment_package.zip .
    cd ../../../
    ```

The final artifact, <mark style="color:$primary;">`build/dist/lambda_deployment_package.zip`</mark>, is now ready for deployment.

**Deploying to AWS Lambda**

While the deployment package can be uploaded manually via the AWS Console, it is strongly recommended to manage production deployments with an Infrastructure as Code (IaC) tool such as AWS SAM, Terraform, or AWS CloudFormation to ensure repeatable and version-controlled infrastructure.

When configuring the Lambda function, use the following settings:

* **Runtime**: Python 3.13
* **Handler**: <mark style="color:$primary;">`guardduty_soar.main.handler`</mark>
* **Execution Role (IAM)**: The function requires an IAM Role with permissions to interact with AWS services. Based on the included playbooks, the role will need permissions for services such as (This list will change and grow as the application grows to cover more services/findings):
  * <mark style="color:$primary;">`iam:*`</mark> (e.g., <mark style="color:$primary;">`GetUser`</mark>, <mark style="color:$primary;">`TagUser`</mark>, <mark style="color:$primary;">`ListAttachedUserPolicies`</mark>)
  * <mark style="color:$primary;">`ec2:*`</mark> (e.g., <mark style="color:$primary;">`DescribeInstances`</mark>, <mark style="color:$primary;">`CreateSnapshot`</mark>)
  * <mark style="color:$primary;">`cloudtrail:LookupEvents`</mark>
  * <mark style="color:$primary;">`ses:SendEmail`</mark>
  * <mark style="color:$primary;">`sns:Publish`</mark>
  * <mark style="color:$primary;">`logs:CreateLogGroup`</mark>, <mark style="color:$primary;">`logs:CreateLogStream`</mark>, <mark style="color:$primary;">`logs:PutLogEvents`</mark> (for CloudWatch Logging)

> **NOTE:** A full list of current permissions used by the code is listed in the [IAM Permissions](iam-permissions.md) section. This allows you to implement least-privilege permissions. There is also an IAM permissions section for testing, that includes more permissions needed for running the test suites.

* **Timeout**: Start with a timeout of 90 seconds. This may need to be adjusted based on the complexity of your playbooks and network latency.
* **Memory**: Start with 256 MB. Increase if your playbooks perform memory-intensive operations.
* **Trigger**: Configure an Amazon EventBridge (CloudWatch Events) rule to trigger the Lambda function for new "GuardDuty Finding" events.
