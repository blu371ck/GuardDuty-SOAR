# S3 Bucket Exposure: Single Bucket Check

## Objective
This scenario validates the full workflow of the `S3BucketExposurePlaybook` for a finding involving a single S3 bucket and an IAM user. It tests the application's ability to perform the full sequence of actions:
- Tag the affected S3 bucket.
- Identify and tag the IAM user principal.
- Quarantine the IAM user by attaching a deny-all policy.
- **Block all public access** on the S3 bucket.
- Send starting and complete notifications.

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- 1 S3 Bucket
- 1 IAM User

## Instructions
### 1. Deploy the Test Infrastructure
Navigate to this directory in your terminal and run the following commands. This will create the AWS resources and automatically generate a populated `event.auto.json` file.
```bash
terraform init
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
After the playbook runs, check the following in your AWS account:
    - S3 Console: The test bucket (soar-s3-exposure-1-...) will have new tags applied. In the Permissions tab, "Block all public access" will be set to On.
    - IAM Console: The test user (soar-s3-test-user-...) will have new tags and the AWSDenyAll policy attached.
    - Notifications: You should receive a "Playbook Complete" notification via your configured channels.

## ⚠️ Cleanup Instructions
Cleanup is a two-step process. You must manually revert the playbook's actions before destroying the Terraform resources.
1. Manually Detach IAM Policy
    - Navigate to the IAM service -> Users.
    - Find the soar-s3-test-user-....
    - Go to the Permissions tab, select the AWSDenyAll policy, and click Detach.

2. Destroy Terraform Resources
This will now successfully delete the IAM user and S3 bucket.
```Bash
terraform destroy --auto-approve
```