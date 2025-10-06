# Installation

This guide will walk you through setting up the GuardDuty SOAR application for production use as a Lambda function. You can run the tests in the application as well, but we cover that all in detail in the [Broken link](broken-reference "mention") section.

#### Prerequisites

* Python 3.13+
* [uv](https://github.com/astral-sh/uv)
* An AWS account with credentials configured locally.
* AWS GuardDuty enabled.
* For EC2, you need VPC flow logs and VPC DNS logs enabled.
* For testing please see the testing section for required permissions and setup.

#### Installation

1. Clone the repository:

```bash
git clone [https://github.com/your-username/guardduty-soar.git](https://github.com/your-username/guardduty-soar.git)
cd guardduty-soar
```

2. Create a virtual environment:

```bash
uv venv
```

### Production Deployment

The goal of a production deployment is to create a lean .zip file containing only the application code and its production dependencies, suitable for AWS Lambda.

1. Build the Production Artifact This process involves installing production dependencies into a temporary directory and then packaging them with your source code.
2. Create a build directory:

```bash
mkdir -p build/dist
```

2. Install production dependencies: Use the requirements.txt lock file to install the exact production dependencies into a package directory.

```bash
uv pip install -r requirements.txt --target build/dist/package
```

3. Copy your application code: Copy the guardduty\_soar package from the src directory into the package directory.

```bash
cp -r src/guardduty_soar build/dist/package/
```

4. Create the Lambda deployment package: Navigate into the package directory and create a .zip file of its contents.

```bash
cd build/dist/package
zip -r ../lambda_deployment_package.zip .
cd ../../../
```

The final artifact, <mark style="color:$primary;">`build/dist/lambda_deployment_package.zip`</mark>, is ready to be deployed.

Deploying to AWS The generated <mark style="color:$primary;">`.zip`</mark> file can be deployed as an AWS Lambda function. A production deployment should be managed with an Infrastructure as Code (IaC) tool like Terraform or AWS SAM.
