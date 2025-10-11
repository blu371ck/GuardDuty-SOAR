# 🔐 IAM Permissions

The GuardDuty-SOAR application requires specific IAM permissions to interact with AWS services. The required permissions differ based on whether you are deploying the application for production or running the end-to-end test suite.

***

#### Production Execution Role Permissions

This set of permissions should be attached to the IAM Role that your AWS Lambda function uses for execution. These permissions grant the application the ability to perform forensic and remediation actions defined in the playbooks.

**Amazon EC2**

* <mark style="color:$primary;">`ec2:CreateNetworkAclEntry`</mark>&#x20;
* <mark style="color:$primary;">`ec2:CreateSnapshot`</mark>&#x20;
* <mark style="color:$primary;">`ec2:CreateTags`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeAddresses`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeInstances`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeInstanceStatus`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeNetworkAcls`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeSecurityGroups`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeSnapshots`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeTags`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DescribeVolumes`</mark>&#x20;
* <mark style="color:$primary;">`ec2:ModifyInstanceAttribute`</mark>&#x20;
* <mark style="color:$primary;">`ec2:RevokeSecurityGroupIngress`</mark>&#x20;
* <mark style="color:$primary;">`ec2:TerminateInstances`</mark>&#x20;

**AWS IAM**

* <mark style="color:$primary;">`iam:AttachRolePolicy`</mark>&#x20;
* <mark style="color:$primary;">`iam:DetachRolePolicy`</mark>&#x20;
* <mark style="color:$primary;">`iam:GetUser`</mark>&#x20;
* <mark style="color:$primary;">`iam:GetUserPolicy`</mark>&#x20;
* <mark style="color:$primary;">`iam:ListAttachedRolePolicies`</mark>&#x20;
* <mark style="color:$primary;">`iam:ListAttachedUserPolicies`</mark>&#x20;
* <mark style="color:$primary;">`iam:ListUserPolicies`</mark>&#x20;
* <mark style="color:$primary;">`iam:TagUser`</mark>&#x20;
* <mark style="color:$primary;">`iam:TagRole`</mark>
* <mark style="color:$primary;">`iam:PutUserPolicy`</mark>&#x20;

**AWS CloudTrail**

* <mark style="color:$primary;">`cloudtrail:LookupEvents`</mark>&#x20;

**Amazon SNS**

* <mark style="color:$primary;">`sns:Publish`</mark>

**Amazon SES**

* <mark style="color:$primary;">`ses:SendEmail`</mark>

***

#### E2E Testing & Deployment Permissions

These are broad permissions required by a developer or a CI/CD pipeline to run the end-to-end test suite, which involves creating and destroying temporary AWS infrastructure. **These permissions are not required for the production Lambda execution role.**

**Amazon EC2**

* All permissions from the production role, plus:
* <mark style="color:$primary;">`ec2:AssociateIamInstanceProfile`</mark>&#x20;
* <mark style="color:$primary;">`ec2:AuthorizeSecurityGroupIngress`</mark>&#x20;
* <mark style="color:$primary;">`ec2:CreateSecurityGroup`</mark>&#x20;
* <mark style="color:$primary;">`ec2:CreateSubnet`</mark>&#x20;
* <mark style="color:$primary;">`ec2:CreateVpc`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DeleteSecurityGroup`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DeleteSubnet`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DeleteSnapshot`</mark>&#x20;
* <mark style="color:$primary;">`ec2:DeleteVpc`</mark>&#x20;
* <mark style="color:$primary;">`ec2:RunInstances`</mark>&#x20;

**AWS IAM**

* All permissions from the production role, plus:
* <mark style="color:$primary;">`iam:AddRoleToInstanceProfile`</mark>&#x20;
* <mark style="color:$primary;">`iam:CreateInstanceProfile`</mark>&#x20;
* <mark style="color:$primary;">`iam:CreatePolicy`</mark>&#x20;
* <mark style="color:$primary;">`iam:CreateRole`</mark>&#x20;
* <mark style="color:$primary;">`iam:CreateUser`</mark>&#x20;
* <mark style="color:$primary;">`iam:DeleteInstanceProfile`</mark>&#x20;
* <mark style="color:$primary;">`iam:DeletePolicy`</mark>
* <mark style="color:$primary;">`iam:DeleteRole`</mark>&#x20;
* <mark style="color:$primary;">`iam:DeleteUser`</mark>&#x20;
* <mark style="color:$primary;">`iam:DeleteUserPolicy`</mark>&#x20;
* <mark style="color:$primary;">`iam:RemoveRoleFromInstanceProfile`</mark>&#x20;

**Amazon SQS**

* <mark style="color:$primary;">`sqs:CreateQueue`</mark>&#x20;
* <mark style="color:$primary;">`sqs:DeleteQueue`</mark>&#x20;
* <mark style="color:$primary;">`sqs:GetQueueAttributes`</mark>
* <mark style="color:$primary;">`sqs:SetQueueAttributes`</mark>&#x20;
* <mark style="color:$primary;">`sqs:ReceiveMessage`</mark>
* <mark style="color:$primary;">`sqs:DeleteMessageBatch`</mark>

**Amazon SNS**

* <mark style="color:$primary;">`sns:Subscribe`</mark>&#x20;
* <mark style="color:$primary;">`sns:Unsubscribe`</mark>&#x20;

**AWS SSM**

* <mark style="color:$primary;">`ssm:GetParameter`</mark>&#x20;

> **Note on SQS/SNS Permissions**\
> \
> These permissions are used by the E2E test suite to create a temporary notification verification channel. The tests dynamically create an SQS queue and subscribe it to the application's SNS topic. This allows the test to programmatically capture and validate the content of the <mark style="color:$primary;">`playbook_started`</mark> and <mark style="color:$primary;">`playbook_completed`</mark> notifications, ensuring the entire workflow is functioning correctly.
