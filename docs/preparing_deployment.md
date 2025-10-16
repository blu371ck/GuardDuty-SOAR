# 🚀 Preparing GuardDuty-SOAR for Deployment

!!! danger "Before you deploy!"
    Amazon GuardDuty is designed to report on a wide range of potential security risks. However, some of these findings may represent activity that is intentional or acceptable within your specific environment (e.g., an application that performs port scanning, or a web server with a publicly accessible port).

    To ensure GuardDuty-SOAR only acts on unintended threats, a two-step process is required for tuning:

    1. **Create Suppression Rules in GuardDuty**: First, you should create suppression rules directly within the AWS GuardDuty service. This tells GuardDuty to automatically archive future findings that match your specific criteria, preventing them from becoming active alerts.
    2. **Update the** `ignored_findings` **Configuration**: Second, you must add the same finding types that you suppressed in GuardDuty to the `ignored_findings` list in your gd.cfg or .env file. This ensures that GuardDuty-SOAR will not execute a playbook, even if a finding is triggered before a suppression rule takes effect.
    
    Both of these steps are essential for a properly tuned deployment that protects your organization from unintended threats without disrupting legitimate operations.

### Preparing GuardDuty-SOAR for Deployment

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

The primary objective for a production deployment is to create a lean `.zip` artifact containing the application source code and its production dependencies, optimized for the AWS Lambda runtime.

**Building the Lambda Deployment Package**

This process isolates production dependencies and packages them with your source code into a single deployment artifact.

**1.  Create a Build Directory: This directory will stage the files for the deployment package.**
```bash
mkdir -p build/dist
```

**2.  Install Production Dependencies: Using the `requirements.txt` lockfile ensures that the exact, tested versions of all dependencies are installed. The `--target` flag directs `uv` to install the packages into a specific directory.**
```bash
uv pip install -r requirements.txt --target build/dist/package
```

!!! warning "Important Note on Build Environments"
    The build process for the AWS Lambda deployment package is architecture-dependent. This is because some project dependencies include compiled code that must match the CPU architecture of the Lambda runtime.

    AWS Lambda offers two architectures:
    * `x86_64` (for Intel/AMD processors)
    * `arm64` (for AWS Graviton/Apple Silicon processors)

    The architecture of your build environment must match the architecture you configure for your Lambda function.

    #### For Users on Intel-based Machines (Linux or macOS)
    You can build the deployment package natively. The resulting artifact will be for the `x86_64` architecture, so you must select `x86_64` when configuring your Lambda function.

    #### For Users on Apple Silicon Macs (M1/M2/M3)

    You have two options:

    1. Build Natively for ARM (**Recommended**): Build the package directly on your Mac. The artifact will be for the `arm64` architecture. You must select `arm64` in your Lambda function's runtime settings.
    2. Cross-Compile for `x86_64`: To deploy to the `x86_64` architecture, you must use the **Docker** method described below.

    #### For Windows Users

    You cannot build natively for **either** Lambda architecture. Your options are:

    * Use Windows Subsystem for Linux (WSL) to build for `x86_64`.
    * Use Docker (**recommended**) to build for either architecture.

    #### Universal Solution: Building with Docker

    Using Docker is the most reliable way to build for a specific architecture, regardless of your local machine.

    *   To build for `x86_64` Lambda functions:

      ```powershell
      docker run --rm -v "${pwd}:/var/task" public.ecr.aws/lambda/python:3.13-x86_64 /bin/sh -c "uv pip install -r requirements.txt --target build/dist/package"
      ```
    *   To build for `arm64` Lambda functions:

      ```powershell
      docker run --rm -v "${pwd}:/var/task" public.ecr.aws/lambda/python:3.13-arm64 /bin/sh -c "uv pip install -r requirements.txt --target build/dist/package"
      ```

**3. Copy Application Source Code: Copy the `guardduty_soar` application package from the `src` directory into the staging directory alongside the dependencies.**

```bash
cp -r src/guardduty_soar build/dist/package/
```

**4. Create the Deployment Package: Navigate into the staging directory and create a `.zip` file containing all its contents.**

```bash
cd build/dist/package
zip -r ../lambda_deployment_package.zip .
cd ../../../
```

The final artifact, `build/dist/lambda_deployment_package.zip`, is now ready for deployment.

**Deploying to AWS Lambda**

While the deployment package can be uploaded manually via the AWS Console, it is strongly recommended to manage production deployments with an Infrastructure as Code (IaC) tool such as AWS SAM, Terraform, or AWS CloudFormation to ensure repeatable and version-controlled infrastructure.

When configuring the Lambda function, use the following settings:

* **Runtime**: Python 3.13
* **Handler**: `guardduty_soar.main.handler`
* **Execution Role (IAM)**: The function requires an IAM Role with permissions to interact with AWS services. Based on the included playbooks, the role will need permissions for services such as (This list will change and grow as the application grows to cover more services/findings):
  * `iam:*` (e.g., `GetUser`, `TagUser`, `ListAttachedUserPolicies`)
  * `ec2:*` (e.g., `DescribeInstances`, `CreateSnapshot`)
  * `cloudtrail:LookupEvents`
  * `ses:SendEmail`
  * `sns:Publish`
  * `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` (for CloudWatch Logging)

!!! note
    A full list of current permissions used by the code is listed in the [IAM Permissions](prod_permissions.md) section. This allows you to implement least-privilege permissions. There is also an IAM permissions section for testing, that includes more permissions needed for running the test suites.

* **Timeout**: Start with a timeout of 90 seconds. This may need to be adjusted based on the complexity of your playbooks and network latency.
* **Memory**: Start with 256 MB. Increase if your playbooks perform memory-intensive operations.
* **Trigger**: Configure an Amazon EventBridge (CloudWatch Events) rule to trigger the Lambda function for new "GuardDuty Finding" events.