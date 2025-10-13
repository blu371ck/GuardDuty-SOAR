# IAM

## These actions interact with AWS IAM principals (Users and Roles).

* <mark style="color:$info;">`AnalyzePermissionsAction`</mark>: Scans a principal's attached and inline IAM policies to identify overly permissive or risky rules, such as wildcard permissions. Can be toggled on-off with <mark style="color:$primary;">analyze\_iam\_permissions</mark> configuration.
* <mark style="color:$info;">`GetIamPrincipalDetails`</mark>: Retrieves detailed information about an IAM user or role, including its creation date, and a full list of its attached and inline policies.
* <mark style="color:$info;">`GetIamCloudTrailHistory`</mark>: Looks up recent CloudTrail events to provide a summary of a principal's latest API activity, aiding in forensic investigation. Customizable range from 1 to 50, with a default value of 25, using <mark style="color:$primary;">`cloudtrail_history_max_results`</mark>.
* <mark style="color:$info;">`IdentifyIamPrincipal`</mark>: Parses the GuardDuty finding to determine the specific IAM principal (User, Role, or Root) involved in the event.
* <mark style="color:$info;">`TagIamPrincipalAction`</mark>: Applies tracking and status tags to an IAM user or role. This action correctly skips the Root user, which cannot be tagged.
