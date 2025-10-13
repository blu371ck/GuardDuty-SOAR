# EC2 Unprotected Port Probe

## Objective
This scenario validates the full workflow of the EC2UnprotectedPortProbePlaybook on an instance. It tests the application's ability to perform a sequence of forensic and remediation actions, including:
- Tagging the instance.
- Pull instance metadata
- Block malicious IP inbound/outbound in ACL
- Remove any public access rules in security group

## Infrastructure Created
This Terraform script will provision the following AWS resources:
- A new VPC and Subnet
- An Internet Gateway and Route Table
- A default Security Group
- An EC2 instance with a profile

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
- EC2 Console: The instance should be in a "shutting-down" or "terminated" state. A new security group named gd-soar-quarantine-i-... will have been created.
- Notifications: You should receive a "Playbook Complete" notification via your configured SES or SNS channel.

## ⚠️ Cleanup Instructions
Cleanup is a two-step process. You must destroy the Terraform resources and manually delete the resources created by the SOAR application.
### 1. Destroy Terraform Resources
This will delete the EC2 instance, VPC, IAM role, and all other resources created by Terraform.
```bash
terraform destroy --auto-approve
```
### 2. Manually Delete SOAR-Created Resources
This playbook does not require any manual cleanup. Terraform will automatically clean up any created resources when you invoke the destroy command.