# S3 Compromise Discovery: Single Bucket Check

## Objective
This scenario validates the workflow of the `S3CompromisedDiscoveryPlaybook` for a finding involving a single S3 bucket and a single IAM user. It tests the application's ability to:
- Tag the affected S3 bucket.
- Identify and tag the IAM user principal from the finding.
- Quarantine the IAM user by attaching a deny-all policy (if configured).
- Send starting and complete notifications.

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- 1 S3 Bucket
- 1 IAM User

## Instructions
### 1. Deploy the Test Infrastructure
Navigate to this directory in your terminal and run the following Terraform commands. This will create the AWS resources and automatically generate a populated `event.auto.json` file.
```bash
# Initialize Terraform providers
terraform init

# Apply the plan to create resources
terraform apply --auto-approve
```
### 2. Invoke the Lambda Function
Use the AWS CLI to trigger your deployed Lambda function, pointing it to the automatically generated event.auto.json file.
```bash
aws lambda invoke \
    --function-name Your-GuardDuty-SOAR-FunctionName \
    --payload file://event.auto.json \
    response.json
```
**NOTE**: You can also use the Lambda console to test by pasting the contents of the event.auto.json into a new test event.

### 3. Verify the Results
After the playbook runs, check the following in your AWS account to confirm the actions were successful:
- **S3 Console**: The test bucket (soar-s3-test-bucket-1-...) will have new tags applied (e.g., SOAR-Status).
- **IAM Console**: The test user (soar-s3-test-user-...) will have new tags applied and, if allow_iam_quarantine is enabled, the AWSDenyAll policy will be attached.
- **Notifications**: You should receive a "Playbook Complete" notification via your configured SES or SNS channel.

## ⚠️ Cleanup Instructions
Cleanup is a two-step process. You must manually revert the playbook's actions before destroying the Terraform resources.
1. Manually Detach IAM Policy
The playbook attaches a policy that Terraform is not aware of. You must detach it first.
    - Navigate to the IAM service -> Users.
    - Find the soar-s3-test-user-....
    - Go to the Permissions tab, select the AWSDenyAll policy, and click Detach.

2. Destroy Terraform Resources
This will now successfully delete the IAM user and S3 bucket.
```bash
terraform destroy --auto-approve
```