# 🔐 IAM Permissions

The GuardDuty-SOAR application requires specific IAM permissions to interact with AWS services. The required permissions differ based on whether you are deploying the application for production or running the end-to-end test suite.

***

#### Production Execution Role Permissions

This set of permissions should be attached to the IAM Role that your AWS Lambda function uses for execution. These permissions grant the application the ability to perform forensic and remediation actions defined in the playbooks.

**Amazon EC2**

* `ec2:CreateNetworkAclEntry`&#x20;
* `ec2:CreateSnapshot`&#x20;
* `ec2:CreateTags`&#x20;
* `ec2:DescribeAddresses`&#x20;
* `ec2:DescribeInstances`&#x20;
* `ec2:DescribeInstanceStatus`&#x20;
* `ec2:DescribeNetworkAcls`&#x20;
* `ec2:DescribeSecurityGroups`&#x20;
* `ec2:DescribeSnapshots`&#x20;
* `ec2:DescribeTags`&#x20;
* `ec2:DescribeVolumes`&#x20;
* `ec2:ModifyInstanceAttribute`&#x20;
* `ec2:RevokeSecurityGroupIngress`&#x20;
* `ec2:TerminateInstances`&#x20;
* `ec2:CreateSecurityGroup`&#x20;
* `ec2:RevokeSecurityGroupEgress`

**AWS IAM**

* `iam:AttachRolePolicy`&#x20;
* `iam:DetachRolePolicy`&#x20;
* `iam:GetUser`&#x20;
* `iam:GetUserPolicy`&#x20;
* `iam:ListAttachedRolePolicies`&#x20;
* `iam:ListAttachedUserPolicies`&#x20;
* `iam:ListUserPolicies`&#x20;
* `iam:TagUser`&#x20;
* `iam:TagRole`
* `iam:PutUserPolicy`&#x20;
* `iam:GetInstanceProfile`

**AWS CloudTrail**

* `cloudtrail:LookupEvents`&#x20;

**Amazon SNS**

* `sns:Publish`

**Amazon SES**

* `ses:SendEmail`

***

#### E2E Testing & Deployment Permissions

These are broad permissions required by a developer or a CI/CD pipeline to run the end-to-end test suite, which involves creating and destroying temporary AWS infrastructure. **These permissions are not required for the production Lambda execution role.**

**Amazon EC2**

* All permissions from the production role, plus:
* `ec2:AssociateIamInstanceProfile`&#x20;
* `ec2:AuthorizeSecurityGroupIngress`&#x20;
* `ec2:CreateSecurityGroup`&#x20;
* `ec2:CreateSubnet`&#x20;
* `ec2:CreateVpc`&#x20;
* `ec2:DeleteSecurityGroup`&#x20;
* `ec2:DeleteSubnet`&#x20;
* `ec2:DeleteSnapshot`&#x20;
* `ec2:DeleteVpc`&#x20;
* `ec2:RunInstances`&#x20;

**AWS IAM**

* All permissions from the production role, plus:
* `iam:AddRoleToInstanceProfile`&#x20;
* `iam:CreateInstanceProfile`&#x20;
* `iam:CreatePolicy`&#x20;
* `iam:CreateRole`&#x20;
* `iam:CreateUser`&#x20;
* `iam:DeleteInstanceProfile`&#x20;
* `iam:DeletePolicy`
* `iam:DeleteRole`&#x20;
* `iam:DeleteUser`&#x20;
* `iam:DeleteUserPolicy`&#x20;
* `iam:RemoveRoleFromInstanceProfile`&#x20;

**Amazon SQS**

* `sqs:CreateQueue`&#x20;
* `sqs:DeleteQueue`&#x20;
* `sqs:GetQueueAttributes`
* `sqs:SetQueueAttributes`&#x20;
* `sqs:ReceiveMessage`
* `sqs:DeleteMessageBatch`

**Amazon SNS**

* `sns:Subscribe`&#x20;
* `sns:Unsubscribe`&#x20;

**AWS SSM**

* `ssm:GetParameter`&#x20;

!!! note "Note on SNS/SQS Permissions"
    These permissions are used by the E2E test suite to create a temporary notification verification channel. The tests dynamically create an SQS queue and subscribe it to the application's SNS topic. This allows the test to programmatically capture and validate the content of the `playbook_started` and `playbook_completed` notifications, ensuring the entire workflow is functioning correctly.
