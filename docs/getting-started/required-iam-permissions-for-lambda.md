# Required IAM Permissions for Lambda

As the deployment destination for this application is a Lambda function, there is a good amount of additional permissions that this role needs in order to invoke the commands that it does. For simplicity, below, we have added them into sections based on the service it is required for. At the end we will also provide a general full policy.

### EC2

```
DeleteQueue
Unsubscribe
DeleteRole
ListAttachedRolePolicies
DetachRolePolicy
RemoveRoleFromInstanceProfile
DeleteSnapshot
DeleteInstanceProfile
DescribeSnapshots
DescribeInstances
DescribeInstances
TerminateInstances
DescribeInstances
ListAttachedRolePolicies
DescribeInstances
DescribeSnapshots
TerminateInstances
DescribeInstances
CreateSnapshot
DescribeInstances
AttachRolePolicy
DescribeInstances
ModifyInstanceAttribute
CreateTags
DescribeInstances
RunInstances
DescribeInstances
GetParameter
Subscribe
SetQueueAttributes
CreateQueue
CreateRole
CreateInstanceProfile
AddRoleToInstanceProfile
```

### IAM



### S3



### Access Key
