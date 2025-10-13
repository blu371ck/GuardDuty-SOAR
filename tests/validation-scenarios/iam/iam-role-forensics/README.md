# IAM Forensics Playbook on Role

### Objective
This scenario validates the full workflow of the `IamForensicsPlaybook` for a finding related to an **IAM Role** (specifically, an `AssumedRole` principal). It tests the application's ability to perform a sequence of forensic actions, including:
* Identifying the IAM principal from the finding.
* Tagging the IAM Role with finding-related information.
* Gathering detailed information about the role, including attached and inline policies.
* Retrieving recent CloudTrail history for the role.
* Analyzing the role's IAM policies for overly permissive rules.

### Infrastructure Created
This Terraform script will provision the following temporary AWS resources:
* An **IAM Role**.
* An **IAM Policy** containing overly permissive rules (`"Action": "*"` and `"Action": "ec2:*"`) to test the analysis action.
* An attachment linking the policy to the role.

---
### Instructions

#### 1. Deploy the Test Infrastructure
Navigate to this directory in your terminal and run the following Terraform commands. This will create the IAM resources and automatically generate a populated `event.auto.json` file.

```bash
# Initialize Terraform providers
terraform init

# Apply the plan to create resources
terraform apply --auto-approve
```
#### 2. Invoke the Lambda Function
Use the AWS CLI to trigger your deployed Lambda function, pointing it directly to the automatically generated event.auto.json file.
```bash
aws lambda invoke \
    --function-name Your-GuardDuty-SOAR-FunctionName \
    --payload file://event.auto.json \
    response.json
```
**NOTE:** You can also use the Lambda console to test by pasting the contents of the `event.auto.json` into a new Lambda test and then invoke that test.

#### 3. Verify the Results
After the playbook runs, you can check the following to confirm the actions were successful:
- Notifications: Inspect the "Playbook Complete" notification. In the enriched_data payload, the permission_analysis field should contain the risks identified from the overly permissive IAM policy.
- IAM Console: Navigate to the IAM service. The temporary role created by Terraform should now have tags applied by the playbook (e.g., GUARDDUTY-SOAR-ID).

### Cleanup
After running `terraform destroy --auto-approve` you do not need to manually clean up any resources.