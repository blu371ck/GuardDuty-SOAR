# IAM

## These actions interact with AWS IAM principals (Users and Roles).

* **`AnalyzePermissionsAction`** (Optional): Scans a principal's attached and inline IAM policies to identify overly permissive rules, such as wildcard permissions. This is controlled by the `analyze_iam_permissions` configuration.
* **`GetIamPrincipalDetailsAction`**: Retrieves detailed information about an IAM user or role, including its creation date and a full list of its attached and inline policies.
* **`GetCloudTrailHistoryAction`**: Looks up recent CloudTrail events to provide a summary of a principal's latest API activity. The number of events is controlled by `cloudtrail_history_max_results`.
* **`IdentifyIamPrincipalAction`**: Parses the GuardDuty finding to determine the specific IAM principal (User, Role, or Root) involved in the event.
* **`TagIamPrincipalAction`**: Applies tracking and status tags to an IAM user or role. This action automatically skips the Root user, which cannot be tagged.
* **`QuarantineIamPrincipalAction`** (Optional): Attaches a deny-all policy to an IAM principal to quarantine it. This is a destructive action controlled by the `allow_iam_quarantine` configuration.