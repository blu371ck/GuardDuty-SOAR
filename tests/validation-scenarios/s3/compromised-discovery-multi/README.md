# S3 Compromise Discovery: Multiple Bucket Check

## Objective
This scenario validates the workflow of the `S3CompromisedDiscoveryPlaybook` for a finding involving **two S3 buckets** and a single IAM user. It tests the application's ability to:
- Iterate through and tag **both** affected S3 buckets.
- Identify and tag the IAM user principal.
- Quarantine the IAM user by attaching a deny-all policy (if configured).
- Send notifications that correctly reference both buckets.

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- 2 S3 Buckets
- 1 IAM User

## Instructions
### 1. Deploy the Test Infrastructure
Navigate to this directory in your terminal and run the following Terraform commands.
```bash
terraform init
terraform apply --auto-approve
```
### 2. Invoke the Lambda Function
Use the AWS CLI to trigger your Lambda function with the generated event.auto.json file.
```bash
aws lambda invoke \
    --function-name Your-GuardDuty-SOAR-FunctionName \
    --payload file://event.auto.json \
    response.json
```
**NOTE**: You can also use the Lambda console to test by pasting the contents of the event.auto.json into a new test event.

### 3. Verify the Results
- **S3 Console**: Both test buckets (soar-s3-test-bucket-1-... and soar-s3-test-bucket-2-...) will have new tags applied.
- **IAM Console**: The test user (soar-s3-test-user-...) will have new tags and, if configured, the AWSDenyAll policy attached.
- **Notifications**: You should receive a "Playbook Complete" notification.

## ⚠️ Cleanup Instructions
1. Manually Detach IAM Policy
    - Navigate to the IAM service -> Users.
    - Find the soar-s3-test-user-....
    - Go to the Permissions tab, select the AWSDenyAll policy, and click Detach.
2. Destroy Terraform Resources
This will now successfully delete the IAM user and both S3 buckets.
```Bash
terraform destroy --auto-approve
```