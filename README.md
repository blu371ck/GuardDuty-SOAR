![guardduty_image](./images/guardduty_soar_logo.png)
![Static Badge](https://img.shields.io/badge/Alpha-BBB?style=plastic&label=Dev%20Stage)
![Static Badge](https://img.shields.io/badge/Python-3.13-BBB?logo=python&logoColor=fff)
![isort](https://img.shields.io/badge/%20Import_Style-isort-BBB?style=plastic&logo=Python&logoColor=FFFFFF)
![Static Badge](https://img.shields.io/badge/Typed-mypy-BBB?style=plastic&logo=python&logoColor=FFFFFF)
![black](https://img.shields.io/badge/Black-BBB?style=plastic&logo=black&logoColor=FFFFFF)
![Static Badge](https://img.shields.io/badge/pytest-BBB?style=plastic&logo=pytest&logoColor=FFFFFF)
![UV](https://img.shields.io/badge/uv-BBB?style=plastic&logo=uv&logoColor=FFFFFF)
![AWS](https://custom-icon-badges.demolab.com/badge/AWS-BBB.svg?logo=aws&logoColor=FFFFFF)

GuardDuty SOAR is a fully serverless, event-driven SOAR (Security Orchestration, Automation, and Response) framework built on AWS. It transforms your AWS security posture from reactive to proactive by providing a robust, extensible, and cost-effective solution to automate the remediation of AWS GuardDuty findings in near real-time.

When GuardDuty detects a potential threat, this framework instantly triggers a customizable Playbook via AWS EventBridge and Lambda. These playbooks execute a sequence of Actions—from tagging and isolating a compromised EC2 instance to blocking malicious IPs—all based on AWS security [recommendations and best practices](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html). The result is a dramatic reduction in incident response time, a minimized blast radius for security events, and a consistent, auditable trail of all actions taken.

## Key Features
This project is built with a focus on modern software architecture, scalability, and testability.
- __Serverless and Cost-Effective__: Built entirely on AWS Lambda, EventBridge, and S3, ensuring you only pay for what you use with zero idle costs and near infinite scalability.
- __Dynamic Playbook Engine__: A powerful, decorator-based registry allows you to add new remediation playbooks for any GuardDuty finding type without modifying the core engine. This makes the framework highly extensible and easy to maintain.
- __Reusable Action Library__: Playbooks are composed of small, single-purpose, and reusable __Actions__ (e.g., IsolateInstance, TagResource, BlockIp). This promotes DRY (Don't Repeat Yourself) principles and simplifies playbook creation.
- __Layered & Decoupled Architecture__: A clean, multi-layered inheritance pattern separates orchestration (Playbooks) from implementation (Actions), making the codebase easy to navigate and test.
- __Comprehensive Testing Suite__: The project includes a multi-layered testing strategy with:
  -  __Unit Tests__: Using botocore.stub to mock the AWS API for fast, isolated testing of individual actions and components.
  -  __Integration Tests__: A dedicated suite that runs against a non-production AWS account to validate real-world interactions with

## Getting Started
To get a local copy up and running, follow these steps.

### Prerequisites
- Python 3.13+
- uv
- AWS credentials configured in your environment (e.g., via ~/.aws/credentials).

### Installation
1. Clone the repository:
```bash
git clone [https://github.com/your-username/guardduty-soar.git](https://github.com/your-username/guardduty-soar.git)
cd guardduty-soar
```
2. Create a virtual environment:
```bash
uv venv
```

## Developer Workflow
This workflow is for developers who want to contribute to the codebase, run tests, and manage dependencies.
1. Setting up the Development Environment
Install all production and development dependencies from the lock file. This ensures your environment is identical to the one used in CI.
```bash
# Install all dependencies
uv pip sync -r requirements-dev.txt

# Install the guardduty-soar package itself in "editable" mode
uv pip install -e .
```
2. Running Tests
The test suite is divided into two categories: unit and integration.
  - __Unit Tests__: These are fast, run in isolation, and do not require AWS credentials. You should run these frequently during development.
```bash
uv run pytest -m "not integration"
```
  - __Integration Tests__: These tests interact with real AWS resources and require valid AWS credentials. They also require you to configure a `gd.test.cfg` file.
    1. Copy the example config: `cp gd.test.cfg.example gd.test.cfg`
    2. Edit `gd.test.cfg` and fill in the values for your AWS test account.
    3. Run the integration tests:
```bash
uv run pytest -m "integration"
```
3. Static Analysis
This project uses mypy for static type checking and black for code formatting.
```bash
# Run type checking
uv run mypy src/

# Format all code
uv run black .
```
4. Managing Dependencies
Do not manually edit the requirements.txt files. All dependencies are managed in pyproject.toml.
  1. Add the new package to the appropriate list in pyproject.toml.
  2. Re-compile the lock files:
```bash
# Update production requirements
uv pip compile pyproject.toml -o requirements.txt

# Update development requirements
uv pip compile pyproject.toml --extra dev -o requirements-dev.txt
```
  3. Sync your local environment:
```bash
uv pip sync -r requirements-dev.txt
```
  4. Commit the changes to pyproject.toml and both requirements files.

## Production Deployment
The goal of a production deployment is to create a lean .zip file containing only the application code and its production dependencies, suitable for AWS Lambda.
1. Build the Production Artifact
This process involves installing production dependencies into a temporary directory and then packaging them with your source code.
  1. Create a build directory:
```bash
mkdir -p build/dist
```
  2. Install production dependencies:
Use the requirements.txt lock file to install the exact production dependencies into a package directory.
```bash
uv pip install -r requirements.txt --target build/dist/package
```
  3. Copy your application code:
Copy the guardduty_soar package from the src directory into the package directory.
```bash
cp -r src/guardduty_soar build/dist/package/
```
  4. Create the Lambda deployment package:
Navigate into the package directory and create a .zip file of its contents.
```bash
cd build/dist/package
zip -r ../lambda_deployment_package.zip .
cd ../../../
```
The final artifact, build/dist/lambda_deployment_package.zip, is ready to be deployed.

2. Deploying to AWS
The generated `.zip` file can be deployed as an AWS Lambda function. A production deployment should be managed with an Infrastructure as Code (IaC) tool like Terraform or AWS SAM.

The IaC template would be responsible for:
- Creating the Lambda function(s) using the `lambda_deployment_package.zip`.
- Setting the correct handler (e.g., `guardduty_soar.main.main`).
- Creating the necessary IAM roles and permissions.
- Creating the EventBridge rules to trigger the Lambda from GuardDuty findings.
- Passing your `gd.cfg` settings to the Lambda as environment variables, which is the best practice for cloud-native configuration.