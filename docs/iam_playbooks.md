# IAM

## IAMForensicsPlaybook

This is a comprehensive forensic playbook designed to respond to a wide array of findings that indicate anomalous or unauthorized activity by an IAM principal (including IAM Users, Assumed Roles, and the Root user). Its primary goal is to enrich the finding with as much contextual information as possible to accelerate a security analyst's investigation.

* **Registered Findings Include:**

| `CredentialAccess:IAMUser/*`                          | `DefenseEvasion:IAMUser/*`                         | `Discovery:IAMUser/*`                          |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `Exfiltration:IAMUser/*`                              | `InitialAcces:IAMUser/*`                           | `PenTest:IAMUser/*`                            |
| `Persistence:IAMUser/*`                               | `Policy:IAMUser/*`                                 | `Recon:IAMUser/*`                              |
| `Stealth:IAMUser/*`                                   | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.custom` | `UnauthorizedAccess:IAMUser/TorIPCaller`           |                                                                                     |

* **Workflow**:
  1. **Identify Principal**: The playbook begins by parsing the GuardDuty finding to accurately identify the IAM principal involved (User, Role, or Root).
  2. **Tag Principal**: It applies tracking tags to the identified principal. This action is automatically skipped for the Root user, as the Root principal cannot be tagged.
  3. **Get Principal Details**: The playbook makes live AWS API calls to gather detailed information about the principal, including its creation date, and all attached and inline IAM policies.
  4. **Get CloudTrail History**: It retrieves recent CloudTrail events associated with the principal to provide a summary of its latest API activities.
  5. **Analyze IAM Permissions (Optional)**: If `analyze_iam_permissions` is `True`, this action scans the principal's IAM policies to identify overly permissive rules, such as wildcard actions (`"*"`) or unrestricted access to sensitive services (`"ec2:*"`). The results are added to the final report.
* **Key Configuration:**
  * `cloudtrail_history_max_results`: Controls how many recent CloudTrail events are retrieved for the report. (Max 50, Min 1, Default 25)
  * `analyze_iam_permissions`: A boolean (`True`/`False`) that enables or disables the IAM policy analysis step.