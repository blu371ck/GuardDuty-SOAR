# 🚀 Preparing for Deployment

!!! danger "Before You Deploy: Tune Your Findings"
    A critical step before deploying to production is to tune the application to your environment.

    1.  **Create Suppression Rules in GuardDuty**: First, create suppression rules within the AWS GuardDuty service to automatically archive findings that are expected or benign in your environment.
    2.  **Update `ignored_findings`**: Second, add the same finding types to the `ignored_findings` list in your configuration (`.env` or `gd.cfg`).

    This two-step process ensures that GuardDuty-SOAR only acts on unintended threats without disrupting legitimate operations.

This guide provides instructions for deploying the GuardDuty-SOAR application as an AWS Lambda function.

---
## Prerequisites

* **Local Environment**:
    * Python 3.13 or newer.
    * `uv` for environment and package management.
* **AWS Environment**:
    * An active AWS account with programmatic access.
    * AWS GuardDuty enabled in the target region(s).

---
## Production Deployment

The goal of a production deployment is to create a lean `.zip` artifact containing your application's source code and its production dependencies.

### Building the Lambda Deployment Package

**1. Create a Staging Directory**
This directory will hold all the files for your deployment package.
```bash
mkdir package
```
**2. Install Your Project and Dependencies** This command installs your guardduty-soar project as a package, along with all its production dependencies, into the package directory.
```Bash
uv pip install . --target ./package
```

!!! note
    The previous `cp -r src/guardduty_soar ...` step is no longer needed, as `uv pip install .` handles the source code packaging automatically.

**3. Create the Deployment Package** Navigate into the package directory and create a .zip file of its contents.

- On macOS/Linux:
```Bash
cd package
zip -r ../deployment.zip .
```

- On Windows (PowerShell):
```powershell
cd package
Compress-Archive -Path * -DestinationPath ..\deployment.zip
```

The final artifact, `deployment.zip`, is now ready to be uploaded to AWS Lambda.

!!! warning "Note on Build Environments & Architectures" 
    Because some Python dependencies contain compiled code, the architecture of your build environment must match the architecture you select for your Lambda function (`x86_64` or `arm64`). Using Docker is the most reliable cross-platform solution. The command below uses the corrected installation step.

    * To build for `x86_64`:
      ```bash
      docker run --rm -v "$(pwd):/var/task" public.ecr.aws/lambda/python:3.13-x86_64 /bin/sh -c "uv pip install . --target ./package"
      ```

## Deploying to AWS Lambda
It is strongly recommended to manage production deployments with an Infrastructure as Code (IaC) tool like AWS SAM or Terraform.

**Key Lambda settings**:

- **Runtime**: Python 3.13
- **Handler**: guardduty_soar.main.handler
- **Execution Role (IAM)**: An IAM Role with permissions to interact with services like EC2, IAM, S3, CloudTrail, SES, and SNS.
- **Timeout**: Start with 90 seconds.
- **Memory**: Start with 256 MB.
- **Trigger**: An Amazon EventBridge rule configured for "GuardDuty Finding" events.

!!! note 
    A detailed list of the required permissions is available in the [IAM Permissions](prod_permissions.md) documentation.