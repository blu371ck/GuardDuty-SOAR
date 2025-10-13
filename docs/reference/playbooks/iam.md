# IAM

## IAMForensicsPlaybook

This is a comprehensive forensic playbook designed to respond to a wide array of findings that indicate anomalous or unauthorized activity by an IAM principal (including IAM Users, Assumed Roles, and the Root user). Its primary goal is to enrich the finding with as much contextual information as possible to accelerate a security analyst's investigation.

* **Registered Findings Include:**

| <mark style="color:$primary;">`CredentialAccess:IAMUser/*`</mark>                          | <mark style="color:$primary;">`DefenseEvasion:IAMUser/*`</mark>                         | <mark style="color:$primary;">`Discovery:IAMUser/*`</mark>                          |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| <mark style="color:$primary;">`Exfiltration:IAMUser/*`</mark>                              | <mark style="color:$primary;">`InitialAcces:IAMUser/*`</mark>                           | <mark style="color:$primary;">`PenTest:IAMUser/*`</mark>                            |
| <mark style="color:$primary;">`Persistence:IAMUser/*`</mark>                               | <mark style="color:$primary;">`Policy:IAMUser/*`</mark>                                 | <mark style="color:$primary;">`Recon:IAMUser/*`</mark>                              |
| <mark style="color:$primary;">`Stealth:IAMUser/*`</mark>                                   | <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`</mark> | <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/MaliciousIPCaller`</mark> |
| <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/MaliciousIPCaller.custom`</mark> | <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/TorIPCaller`</mark>           |                                                                                     |

* **Workflow**:
  1. **Identify Principal**: The playbook begins by parsing the GuardDuty finding to accurately identify the IAM principal involved (User, Role, or Root).
  2. **Tag Principal**: It applies tracking tags to the identified principal. This action is automatically skipped for the Root user, as the Root principal cannot be tagged.
  3. **Get Principal Details**: The playbook makes live AWS API calls to gather detailed information about the principal, including its creation date, and all attached and inline IAM policies.
  4. **Get CloudTrail History**: It retrieves recent CloudTrail events associated with the principal to provide a summary of its latest API activities.
  5. **Analyze IAM Permissions (Optional)**: If <mark style="color:$primary;">`analyze_iam_permissions`</mark> is <mark style="color:$primary;">`True`</mark>, this action scans the principal's IAM policies to identify overly permissive rules, such as wildcard actions (<mark style="color:$primary;">`"*"`</mark>) or unrestricted access to sensitive services (<mark style="color:$primary;">`"ec2:*"`</mark>). The results are added to the final report.
* **Key Configuration:**
  * <mark style="color:$primary;">`cloudtrail_history_max_results`</mark>: Controls how many recent CloudTrail events are retrieved for the report. (Max 50, Min 1, Default 25)
  * <mark style="color:$primary;">`analyze_iam_permissions`</mark>: A boolean (<mark style="color:$primary;">`True`</mark>/<mark style="color:$primary;">`False`</mark>) that enables or disables the IAM policy analysis step.
