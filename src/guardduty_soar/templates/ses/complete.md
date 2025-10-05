Subject: [GuardDuty-SOAR] {final_status_emoji} Response Complete: {finding_type}

The automated security playbook for finding {finding_id} has completed.

## Finding Summary:
- __Title__: {finding_title}
- __Severity__: {finding_severity}
- __Description__: {finding_description}

## Affected Resource Details (Enriched):
- __Instance ID__: {instance_id}
- __Instance Type__: {instance_type}
- __Public IP__: {public_ip}
- __Private IP__: {private_ip}
- __VPC ID__: {vpc_id}
- __Subnet ID__: {subnet_id}
- __IAM Profile ARN__: {iam_profile}
- __Tags__: {instance_tags}

## Actions Summary:
{actions_summary}

## Final Status: {final_status_message}
[Link to Finding in AWS Console]({console_link})