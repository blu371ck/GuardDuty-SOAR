# 🔐 IAM Permissions

The GuardDuty-SOAR application requires specific IAM permissions to interact with AWS services. Permissions differ for production execution versus development testing.

---
## Production Execution Role Permissions

This set of permissions should be attached to the IAM Role used by your AWS Lambda function.

### Amazon EC2

* `ec2:CreateNetworkAclEntry`
* `ec2:CreateSecurityGroup`
* `ec2:CreateSnapshot`
* `ec2:CreateTags`
* `ec2:DescribeInstances`
* `ec2:DescribeNetworkAcls`
* `ec2:DescribeSecurityGroups`
* `ec2:ModifyInstanceAttribute`
* `ec2:RevokeSecurityGroupEgress`
* `ec2:RevokeSecurityGroupIngress`
* `ec2:TerminateInstances`

### AWS IAM

* `iam:AttachRolePolicy`
* `iam:AttachUserPolicy`
* `iam:GetInstanceProfile`
* `iam:GetRole`
* `iam:GetUser`
* `iam:ListAttachedRolePolicies`
* `iam:ListAttachedUserPolicies`
* `iam:ListRolePolicies`
* `iam:ListUserPolicies`
* `iam:TagRole`
* `iam:TagUser`

### Amazon S3

* `s3:GetBucketTagging`
* `s3:GetEncryptionConfiguration`
* `s3:GetBucketPublicAccessBlock`
* `s3:GetBucketPolicy`
* `s3:PutBucketTagging`
* `s3:PutBucketPublicAccessBlock`
* `s3:GetBucketEncryption`
* `s3:GetBucketVersioning`
* `s3:GetBucketLogging`

### AWS CloudTrail

* `cloudtrail:LookupEvents`

### Amazon SNS & SES

* `sns:Publish`
* `ses:SendEmail`

---
## E2E Testing & Deployment Permissions

These broad permissions are required by a developer or CI/CD pipeline to run the test suite, which creates and destroys temporary infrastructure. **These are not required for the production Lambda role.**

### Amazon EC2

* All production permissions, plus: 
* `ec2:AssociateIamInstanceProfile` 
* `ec2:AuthorizeSecurityGroupIngress`
* `ec2:CreateSubnet`
* `ec2:CreateVpc`
* `ec2:DeleteSecurityGroup`
* `ec2:DeleteSubnet`
* `ec2:DeleteSnapshot`
* `ec2:DeleteVpc`
* `ec2:RunInstances`

### AWS IAM

* All production permissions, plus:
* `iam:AddRoleToInstanceProfile`
* `iam:CreateAccessKey`
* `iam:CreateInstanceProfile`
* `iam:CreatePolicy`
* `iam:CreateRole`
* `iam:CreateUser`
* `iam:DeleteAccessKey`
* `iam:DeleteInstanceProfile`
* `iam:DeletePolicy`
* `iam:DeleteRole`
* `iam:DeleteUser`
* `iam:DeleteUserPolicy`
* `iam:DetachRolePolicy`
* `iam:DetachUserPolicy`
* `iam:PutUserPolicy`
* `iam:RemoveRoleFromInstanceProfile`

### Amazon S3

* All production permissions, plus: 
* `s3:CreateBucket`
* `s3:DeleteBucket`

### Amazon SQS & SNS
* `sqs:*` and `sns:*` (for creating temporary notification channels)

### AWS SSM
* `ssm:GetParameter`