# 🎛️ Testing Configurations

Testing configurations are managed via a <mark style="color:$primary;">`.env`</mark> file in the project root. This allows you to override the default production settings from <mark style="color:$primary;">`gd.cfg`</mark> for your local development environment. This is primarily used to direct AWS API calls to a dedicated test account, enable verbose logging for troubleshooting, and modify playbook behaviors during development.

#### Environment Variable Naming Convention

All parameters available in the <mark style="color:$primary;">`gd.cfg`</mark> file can be set as environment variables. The naming convention is to take the parameter name, prefix it with <mark style="color:$primary;">`GD_`</mark>, and convert the entire string to uppercase.

For example:

* <mark style="color:$primary;">`gd.cfg`</mark>: <mark style="color:$primary;">`[General]`</mark> -> <mark style="color:$primary;">`log_level`</mark> becomes <mark style="color:$primary;">`.env`</mark>: <mark style="color:$primary;">`GD_LOG_LEVEL`</mark>
* <mark style="color:$primary;">`gd.cfg`</mark>: <mark style="color:$primary;">`[EC2]`</mark> -> <mark style="color:$primary;">`quarantine_security_group_id`</mark> becomes <mark style="color:$primary;">`.env`</mark>: <mark style="color:$primary;">`GD_QUARANTINE_SG_ID`</mark>

The following is a complete list of the available environment variables and their corresponding <mark style="color:$primary;">`gd.cfg`</mark> parameters.

### \[General]

| .env                 | gd.cfg            |
| -------------------- | ----------------- |
| `GD_LOG_LEVEL`       | `log_level`       |
| `GD_BOTO_LOG_LEVEL`  | `boto_log_level`  |
| `GD_IGNORE_FINDINGS` | `ignore_findings` |

### \[Notifications]

| .env                          | gd.cfg                     |
| ----------------------------- | -------------------------- |
| `GD_ALLOW_SES`                | `allow_ses`                |
| `GD_REGISTERED_EMAIL_ADDRESS` | `registered_email_address` |
| `GD_ALLOW_SNS`                | `allow_sns`                |
| `GD_TOPIC_ARN`                | `sns_topic_arn`            |

### \[EC2]

| .env                              | gd.cfg                         |
| --------------------------------- | ------------------------------ |
| `GD_QUARANTINE_SECURITY_GROUP_ID` | `quarantine_security_group_id` |
| `GD_IAM_DENY_ALL_POLICY_ARN`      | `iam_deny_all_policy_arn`      |
| `GD_SNAPSHOT_DESCRIPTION_PREFIX`  | `snapshot_description_prefix`  |
| `GD_ALLOW_TERMINATE`              | `allow_terminate`              |
| `GD_ALLOW_REMOVE_PUBLIC_ACCESS`   | `allow_remove_public_access`   |

### \[IAM]

| .env                                | gd.cfg                           |
| ----------------------------------- | -------------------------------- |
| `GD_CLOUDTRAIL_HISTORY_MAX_RESULTS` | `cloudtrail_history_max_results` |
| `GD_ANALYZE_IAM_PERMISSIONS`        | `analyze_iam_permissions`        |
