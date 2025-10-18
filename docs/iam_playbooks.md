# IAM

## IAMForensicsPlaybook

This is a comprehensive forensic playbook designed to respond to a wide array of findings that indicate anomalous or unauthorized activity by an IAM principal (Users, Roles, and the Root user). Its primary goal is to enrich the finding with as much contextual information as possible to accelerate a security analyst's investigation.

* **Registered Findings Include**:
    * `CredentialAccess:IAMUser/*`
    * `DefenseEvasion:IAMUser/*`
    * `Discovery:IAMUser/*`
    * `Exfiltration:IAMUser/*`
    * `InitialAccess:IAMUser/*`
    * `PenTest:IAMUser/*`
    * `Persistence:IAMUser/*`
    * `Policy:IAMUser/*`
    * `Recon:IAMUser/*`
    * `Stealth:IAMUser/*`
    * `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`
    * `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
    * `UnauthorizedAccess:IAMUser/MaliciousIPCaller.custom`
    * `UnauthorizedAccess:IAMUser/TorIPCaller`

* **Workflow**:
    1.  **Identify Principal**: Parses the GuardDuty finding to identify the IAM principal.
    2.  **Tag Principal**: Applies tracking tags to the identified principal (skipped for the Root user).
    3.  **Get Principal Details**: Gathers detailed information about the principal, including its creation date and all attached and inline IAM policies.
    4.  **Get CloudTrail History**: Retrieves recent CloudTrail events associated with the principal to summarize its latest API activities.
    5.  **Analyze IAM Permissions (Optional)**: Scans the principal's IAM policies for overly permissive rules (e.g., `Action: "*"` on `Resource: "*"`).
    6.  **Quarantine Caller Identity (Optional)**: Attaches a deny-all policy to the IAM principal.

* **Key Configurations**:
    * `analyze_iam_permissions`: If `true`, Step 5 will be executed. Defaults to `true`.
    * `allow_iam_quarantine`: If `true`, Step 6 will be executed. Defaults to `false`.
    * `cloudtrail_history_max_results`: Controls how many recent CloudTrail events are retrieved in Step 4. Defaults to `25`.