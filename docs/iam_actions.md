# IAM

## These actions interact with AWS IAM principals (Users and Roles).

* `AnalyzePermissionsAction`: Scans a principal's attached and inline IAM policies to identify overly permissive or risky rules, such as wildcard permissions. Can be toggled on-off with `analyze_iam_permissions` configuration.
* `GetIamPrincipalDetails`: Retrieves detailed information about an IAM user or role, including its creation date, and a full list of its attached and inline policies.
* `GetIamCloudTrailHistory`: Looks up recent CloudTrail events to provide a summary of a principal's latest API activity, aiding in forensic investigation. Customizable range from 1 to 50, with a default value of 25, using `cloudtrail_history_max_results`.
* `IdentifyIamPrincipal`: Parses the GuardDuty finding to determine the specific IAM principal (User, Role, or Root) involved in the event.
* `TagIamPrincipalAction`: Applies tracking and status tags to an IAM user or role. This action correctly skips the Root user, which cannot be tagged.