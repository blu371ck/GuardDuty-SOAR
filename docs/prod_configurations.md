# ⚙️ Configurations

The behavior of the GuardDuty-SOAR application is controlled by the `gd.cfg` file, which uses a standard INI format. This file serves as the central point for customizing playbook actions and notification settings without modifying the source code. The configuration is loaded once when the Lambda function starts.

### General

This section contains application-wide settings for logging and core functionality.

<table><thead><tr><th width="186">Settings</th><th width="260">Description</th><th width="294">Options</th></tr></thead><tbody><tr><td><code>log_level</code></td><td>Sets the logging verbosity for the main application. <code>DEBUG</code> is highly verbose for development, while <code>INFO</code> is recommended for production.</td><td><code>DEBUG</code>, <code>INFO</code>, <code>WARNING</code>, <code>ERROR</code>, <code>CRITICAL</code></td></tr><tr><td><code>boto_log_level</code></td><td>Controls the logging verbosity for the underlying AWS SDK (Boto3). Use <code>DEBUG</code> only when diagnosing issues with AWS API calls.</td><td><code>DEBUG</code>, <code>INFO</code>, <code>WARNING</code>, <code>ERROR</code>, <code>CRITICAL</code></td></tr><tr><td><code>ignored_findings</code></td><td>A multiline list of GuardDuty finding types that the application should ignore entirely. Each finding type must be on a new, indented line.</td><td>A list of GuardDuty finding types</td></tr></tbody></table>

### EC2

These parameters control the behavior of playbooks and actions that target Amazon EC2 resources.

<table><thead><tr><th width="269">Settings</th><th width="476">Description</th></tr></thead><tbody><tr><td><code>snapshot_description_prefix</code></td><td>A string prefix used for the descriptions of EBS snapshots created during forensic procedures (e.g., <code>GD-SOAR-Snapshot-</code>).</td></tr><tr><td><code>allow_terminate</code></td><td>(<strong>Destructive</strong>) If <code>True</code>, allows playbooks to terminate compromised EC2 instances. Use with caution.</td></tr><tr><td><code>allow_remove_public_access</code></td><td>If <code>True</code>, allows playbooks to remove rules that grant public access (e.g., <code>0.0.0.0/0</code>) from an instance's security group. Disable this if your instances are intentionally public-facing (e.g., web servers).</td></tr></tbody></table>

### IAM

These parameters control the behavior of playbooks that target IAM principals.

| Settings                                                              | Description                                                                                                                                             |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cloudtrail_history_max_results` | The maximum number of recent CloudTrail events to retrieve for an IAM principal involved in a finding. (Min: 1, Max: 50, Default: 25)                   |
| `analyze_iam_permissions`        | If `True`, enables the analysis of a principal's attached and inline policies to identify overly permissive rules. |

### Notifications

Configure one or more channels to receive alerts about findings and remediation actions. For each channel enabled (e.g., `allow_ses = True`), the corresponding parameters are required.

<table><thead><tr><th width="318">Setting</th><th>Description</th></tr></thead><tbody><tr><td><code>allow_ses</code></td><td>If <code>True</code>, enables notifications via Amazon Simple Email Service (SES).</td></tr><tr><td><code>registered_email_address</code></td><td>The destination email address for alerts. This address must be verified within Amazon SES.</td></tr><tr><td><code>allow_sns</code></td><td>If <code>True</code>, enables notifications via Amazon Simple Notification Service (SNS).</td></tr><tr><td><code>sns_topic_arn</code></td><td>The ARN of the SNS topic where notification messages will be published.</td></tr></tbody></table>