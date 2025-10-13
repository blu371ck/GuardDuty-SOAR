# EC2 Brute Force Target Playbook

## Objective
This scenario validates the full workflow of the EC2BruteForcePlaybook on an instance, when the instance is the TARGET. This tests the application's ability to perform a sequence of forensic and remediation actions, including:
- Tagging the instance.
- Gather Instance metadata
- Block the malicious IP in the Network ACL

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- A new VPC and Subnet
- A default Security Group
- An EC2 instance with no profile

## Instructions
### 1. Deploy the Test Infrastructure
Navigate to this directory in your terminal and run the following Terraform commands. This will create the AWS resources and automatically generate a populated event.auto.json file.
```bash
# Initialize Terraform providers
terraform init

# Apply the plan to create resources
terraform apply --auto-approve
```
### 2. Invoke the Lambda Function
Use the AWS CLI to trigger your deployed Lambda function, pointing it directly to the automatically generated event.auto.json file.
```bash
aws lambda invoke \
    --function-name Your-GuardDuty-SOAR-FunctionName \
    --payload file://event.auto.json \
    response.json
```
**NOTE:** You can also use the Lambda console to test by pasting the contents of the `event.auto.json` into a new Lambda test and then invoke that test.

### 3. Verify the Results
After the playbook runs, you can check the following in your AWS account to confirm the actions were successful:
- VPC Console: Add rule should be added to the inbound and outbound rules for this "malicious ip" address.
- Notifications: You should receive a "Playbook Complete" notification via your configured SES or SNS channel.

## ⚠️ Cleanup Instructions
Cleanup is a two-step process. You must destroy the Terraform resources and manually delete the resources created by the SOAR application.

### 1. Destroy Terraform Resources
This will delete the EC2 instance, VPC, IAM role, and all other resources created by Terraform.
```bash
terraform destroy --auto-approve
```

### 2. Manually Delete SOAR-Created Resources
This playbook requires no manual deletion. All items are cleaned up by the Terraform script.