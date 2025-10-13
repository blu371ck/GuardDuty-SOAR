# ⚙️ Configurations

The behavior of the GuardDuty-SOAR application is controlled by the <mark style="color:$primary;">`gd.cfg`</mark> file, which uses a standard INI format. This file serves as the central point for customizing playbook actions and notification settings without modifying the source code. The configuration is loaded once when the Lambda function starts.

### General

This section contains application-wide settings for logging and core functionality.

<table><thead><tr><th width="186">Settings</th><th width="260">Description</th><th width="294">Options</th><th>Default</th></tr></thead><tbody><tr><td><mark style="color:$primary;"><code>log_level</code></mark></td><td>Sets the logging verbosity for the main application. <mark style="color:$primary;"><code>DEBUG</code></mark> is highly verbose for development, while <mark style="color:$primary;"><code>INFO</code></mark> is recommended for production.</td><td><mark style="color:$primary;"><code>DEBUG</code></mark>, <mark style="color:$primary;"><code>INFO</code></mark>, <mark style="color:$primary;"><code>WARNING</code></mark>, <mark style="color:$primary;"><code>ERROR</code></mark>, <mark style="color:$primary;"><code>CRITICAL</code></mark></td><td><mark style="color:$primary;"><code>INFO</code></mark></td></tr><tr><td><mark style="color:$primary;"><code>boto_log_level</code></mark></td><td>Controls the logging verbosity for the underlying AWS SDK (Boto3). Use <mark style="color:$primary;"><code>DEBUG</code></mark> only when diagnosing issues with AWS API calls.</td><td><mark style="color:$primary;"><code>DEBUG</code></mark>, <mark style="color:$primary;"><code>INFO</code></mark>, <mark style="color:$primary;"><code>WARNING</code></mark>, <mark style="color:$primary;"><code>ERROR</code></mark>, <mark style="color:$primary;"><code>CRITICAL</code></mark></td><td><mark style="color:$primary;"><code>WARNING</code></mark></td></tr><tr><td><mark style="color:$primary;"><code>ignored_findings</code></mark></td><td>A multiline list of GuardDuty finding types that the application should ignore entirely. Each finding type must be on a new, indented line.</td><td>A list of GuardDuty finding types</td><td>(none)</td></tr></tbody></table>

### EC2

These parameters control the behavior of playbooks and actions that target Amazon EC2 resources.

<table><thead><tr><th width="269">Settings</th><th width="476">Description</th></tr></thead><tbody><tr><td><mark style="color:$primary;"><code>snapshot_description_prefix</code></mark></td><td>A string prefix used for the descriptions of EBS snapshots created during forensic procedures (e.g., <mark style="color:$primary;"><code>GD-SOAR-Snapshot-</code></mark>).</td></tr><tr><td><mark style="color:$primary;"><code>allow_terminate</code></mark></td><td>(<strong>Destructive</strong>) If <mark style="color:$primary;"><code>True</code></mark>, allows playbooks to terminate compromised EC2 instances. Use with caution.</td></tr><tr><td><mark style="color:$primary;"><code>allow_remove_public_access</code></mark></td><td>If <mark style="color:$primary;"><code>True</code></mark>, allows playbooks to remove rules that grant public access (e.g., <mark style="color:$primary;"><code>0.0.0.0/0</code></mark>) from an instance's security group. Disable this if your instances are intentionally public-facing (e.g., web servers).</td></tr></tbody></table>

### IAM

These parameters control the behavior of playbooks that target IAM principals.

| Settings                                                              | Description                                                                                                                                             |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <mark style="color:$primary;">`cloudtrail_history_max_results`</mark> | The maximum number of recent CloudTrail events to retrieve for an IAM principal involved in a finding. (Min: 1, Max: 50, Default: 25)                   |
| <mark style="color:$primary;">`analyze_iam_permissions`</mark>        | If <mark style="color:$primary;">`True`</mark>, enables the analysis of a principal's attached and inline policies to identify overly permissive rules. |

### Notifications

Configure one or more channels to receive alerts about findings and remediation actions. For each channel enabled (e.g., `allow_ses = True`), the corresponding parameters are required.

<table><thead><tr><th width="318">Setting</th><th>Description</th></tr></thead><tbody><tr><td><mark style="color:$primary;"><code>allow_ses</code></mark></td><td>If <mark style="color:$primary;"><code>True</code></mark>, enables notifications via Amazon Simple Email Service (SES).</td></tr><tr><td><mark style="color:$primary;"><code>registered_email_address</code></mark></td><td>The destination email address for alerts. This address must be verified within Amazon SES.</td></tr><tr><td><mark style="color:$primary;"><code>allow_sns</code></mark></td><td>If <mark style="color:$primary;"><code>True</code></mark>, enables notifications via Amazon Simple Notification Service (SNS).</td></tr><tr><td><mark style="color:$primary;"><code>sns_topic_arn</code></mark></td><td>The ARN of the SNS topic where notification messages will be published.</td></tr></tbody></table>
