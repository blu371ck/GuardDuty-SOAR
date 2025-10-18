# S3 Bucket Exposure: Multiple Bucket Check

## Objective
This scenario validates the `S3BucketExposurePlaybook` for a finding involving **two S3 buckets**. It tests the application's ability to:
- Iterate through and tag **both** affected S3 buckets.
- Iterate through and **block public access** on **both** S3 buckets.
- Identify, tag, and quarantine the single IAM user principal.

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- 2 S3 Buckets
- 1 IAM User

## Instructions
### 1. Deploy the Test Infrastructure
```bash
terraform init
terraform apply --auto-approve
```
#### 2. Invoke the Lambda Function

```Bash
aws lambda invoke \
    --function-name Your-GuardDuty-SOAR-FunctionName \
    --payload file://event.auto.json \
    response.json
```
**NOTE**: You can also use the Lambda console to test by pasting the contents of the event.auto.json into a new test event.

### 3. Verify the Results
    - S3 Console: Both test buckets will have new tags applied and will have "Block all public access" set to On.
    - IAM Console: The test user will have new tags and the AWSDenyAll policy attached.
    - Notifications: You should receive a "Playbook Complete" notification.

## ⚠️ Cleanup Instructions
1. Manually Detach IAM Policy
    - Navigate to the IAM service -> Users and find the soar-s3-test-user-....
    - Go to the Permissions tab, select the AWSDenyAll policy, and click Detach.

2. Destroy Terraform Resources

```Bash
terraform destroy --auto-approve
```