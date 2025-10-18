# S3
!!! note
    A note on **Directory Buckets**: For any S3-related finding, the playbooks will first check the type of bucket involved. If a bucket is identified as a `DirectoryBucket`, all actions that are incompatible with that bucket type (such as tagging, enriching details, and blocking public access) will be automatically and safely skipped. IAM-related actions will still be executed.

---

## S3CompromisedDiscoveryPlaybook

This is the foundational S3 playbook, providing a comprehensive forensic and remediation workflow. It is inherited by the other S3 playbooks. This playbook is triggered by findings that indicate anomalous discovery-related API calls are being made against S3 buckets by a specific IAM identity.

* **Registered Findings Include**:
    * `Discovery:S3/AnomalousBehavior`
    * `Discovery:S3/MaliciousIPCaller`
    * `Discovery:S3/MaliciousIPCaller.Custom`
    * `Discovery:S3/TorIPCaller`
    * `PenTest:S3/KaliLinux`
    * `PenTest:S3/ParrotLinux`
    * `PenTest:S3/PentooLinux`
    * `Stealth:S3/ServerAccessLoggingDisabled`
    * `UnauthorizedAccess:S3/MaliciousIPCaller.Custom`
    * `UnauthorizedAccess:S3/TorIPCaller`

* **Workflow**:
    1.  **Tag S3 Bucket**: Applies standard SOAR-related tags to each non-directory bucket in the finding.
    2.  **Identify IAM Principal**: Identifies the IAM user or role involved in the finding.
    3.  **Tag IAM Principal**: Applies standard SOAR-related tags to the identified IAM principal.
    4.  **Enrich S3 Finding**: Gathers detailed configuration data for each non-directory bucket, including policy, encryption, and versioning status.
    5.  **Quarantine Caller Identity**: (Optional) Attaches a deny-all policy to the IAM principal.

* **Key Configurations**:
    * `allow_iam_quarantine`: If `true`, Step 5 will be executed. Defaults to `false`.

---

## S3DataLossPreventionPlaybook

This playbook handles findings where there is a potential for data loss through exfiltration or deletion. It inherits from `S3CompromisedDiscoveryPlaybook` and adds a final step to gather S3-specific API call history.

* **Registered Findings Include**:
    * `Exfiltration:S3/AnomalousBehavior`
    * `Exfiltration:S3/MaliciousIPCaller`
    * `Impact:S3/AnomalousBehavior.Delete`
    * `Impact:S3/AnomalousBehavior.Write`
    * `Impact:S3/MaliciousIPCaller`

* **Workflow**:
    1.  First, executes all five steps from the `S3CompromisedDiscoveryPlaybook`.
    2.  **Get S3 CloudTrail History**: Gathers recent CloudTrail events specifically for the `s3.amazonaws.com` event source that were invoked by the identified IAM principal.

* **Key Configurations**:
    * `allow_iam_quarantine`: Controls the quarantine step inherited from the parent playbook.
    * `cloudtrail_history_max_results`: Controls how many CloudTrail events are retrieved in the final step.

---

## S3BucketExposurePlaybook

This playbook remediates findings where an S3 bucket has been exposed to the public. It inherits from `S3CompromisedDiscoveryPlaybook` and adds a final remediation step to lock down the bucket.

* **Registered Findings Include**:
    * `Policy:S3/BucketPublicAccessGranted`

* **Workflow**:
    1.  First, executes all five steps from the `S3CompromisedDiscoveryPlaybook`.
    2.  **Attach Public Access Block**: (Optional) Applies the "block all public access" setting to each non-directory bucket in the finding.

* **Key Configurations**:
    * `allow_iam_quarantine`: Controls the quarantine step inherited from the parent playbook.
    * `allow_s3_public_block`: If `true`, the final remediation step will be executed. Defaults to `false`.