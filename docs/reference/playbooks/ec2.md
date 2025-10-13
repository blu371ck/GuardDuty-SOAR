# EC2

## EC2InstanceCompromisePlaybook

This is the most comprehensive and aggressive response playbook, designed for findings that strongly indicate an EC2 instance has been compromised. Its primary goal is to neutralize the threat and preserve evidence for forensic analysis.

* **Registered Findings Include**:

<table data-header-hidden data-full-width="false"><thead><tr><th width="252"></th><th width="258"></th><th></th></tr></thead><tbody><tr><td><mark style="color:$primary;"><code>Backdoor:EC2/*</code></mark></td><td><mark style="color:$primary;"><code>Behavior:EC2/*</code></mark></td><td><mark style="color:$primary;"><code>CryptoCurrency:EC2/*</code></mark></td></tr><tr><td><mark style="color:$primary;"><code>DefenseEvasion:EC2/*</code></mark></td><td><mark style="color:$primary;"><code>Impact:EC2/*</code></mark></td><td><mark style="color:$primary;"><code>Recon:EC2/Portscan</code></mark></td></tr><tr><td><mark style="color:$primary;"><code>Trojan:EC2/*</code></mark></td><td><mark style="color:$primary;"><code>UnauthorizedAccess:EC2/MaliciousIPCaller.Customer</code></mark></td><td><mark style="color:$primary;"><code>UnauthorizedAccess:EC2/TorClient</code></mark></td></tr><tr><td><mark style="color:$primary;"><code>UnauthorizedAccess:EC2/TorRelay</code></mark></td><td><mark style="color:$primary;"><code>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS</code></mark></td><td><mark style="color:$primary;"><code>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS</code></mark></td></tr></tbody></table>

{% hint style="info" %}
**A note on** <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`</mark> **and** <mark style="color:$primary;">`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`</mark>**, these two findings are related to an EC2 instances profile becoming compromised. So, we run the** <mark style="color:$primary;">`EC2InstanceCompromisePlaybook`</mark> **as it also places a deny-all policy on the instance profile, which will render the credentials useless.**
{% endhint %}

* **Workflow**:
  1. **Tag Instance**: Applies tags to the instance for tracking (<mark style="color:$primary;">`SOAR-Status`</mark>, <mark style="color:$primary;">`GUARDDUTY-SOAR-I`</mark>`D`, etc.).
  2. **Enrich Finding**: Gathers live metadata from the instance (VPC ID, security groups, etc.) to enrich the notification.
  3. **Isolate Instance**: Dynamically creates a new, deny-all security group in the instance's VPC and applies it, effectively taking the instance off the network.
  4. **Quarantine IAM Role**: Attaches the AWS managed <mark style="color:$primary;">`AWSDenyAll`</mark> policy to the instance's IAM role, revoking its permissions.
  5. **Create Snapshots**: Takes snapshots of all EBS volumes attached to the instance for forensic preservation.
  6. **Terminate Instance (Optional)**: If <mark style="color:$primary;">`allow_terminate`</mark> is <mark style="color:$primary;">`True`</mark> in the configuration, this action terminates the compromised instance.
* Key Configuration:
  * <mark style="color:$primary;">`allow_terminate`</mark>: Controls whether the playbook is permitted to terminate the instance.

## EC2BruteForcePlaybook

This playbook handles findings related to brute-force attacks and has two distinct response paths based on the role of the instance in the finding.

* **Registered Findings Include**:

| <mark style="color:$primary;">`UnauthorizedAccess:EC2/RDPBruteForce`</mark> | <mark style="color:$primary;">`UnauthorizedAccess:EC2/SSHBruteForce`</mark> |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------- |

* **Workflow**:
  * If the instance is the <mark style="color:$primary;">`TARGET`</mark> (i.e., it is being attacked):
    1. **Tag Instance**: Applies tracking tags to the instance.
    2. **Enrich Finding**: Gathers live metadata.
    3. **Block Malicious IP**: Adds deny rules to the subnet's Network ACL (NACL) to block the attacker's IP address.
  * If the instance is the <mark style="color:$primary;">`SOURCE`</mark> (i.e., it is performing the attack):
    * This indicates the instance is compromised. The playbook will execute the full [<mark style="color:$primary;">`EC2InstanceCompromisePlaybook`</mark>](ec2.md#ec2instancecompromiseplaybook) workflow described above.

## EC2CredentialExfiltrationPlaybook

This playbook is triggered by findings that suggest IAM credentials may have been exfiltrated from an EC2 instance. The response is similar to a full compromise but is non-destructive by default.

* **Registered Findings Include:**

<table data-header-hidden><thead><tr><th width="410"></th></tr></thead><tbody><tr><td><mark style="color:$primary;"><code>UnauthorizedAccess:EC2/MetadataDNSRebind</code></mark></td></tr></tbody></table>

* **Workflow**:
  1. **Tag Instance**: Applies tracking tags.
  2. **Enrich Finding**: Gathers live metadata.
  3. **Isolate Instance**: Dynamically creates and applies a deny-all security group.
  4. **Quarantine IAM Role**: Attaches the <mark style="color:$primary;">`AWSDenyAll`</mark> policy to the instance's IAM role.
  5. **Create Snapshots**: Takes snapshots of all attached EBS volumes.

{% hint style="info" %}
This playbook intentionally does not terminate the instance, allowing an analyst to perform a live investigation.
{% endhint %}

## EC2UnprotectedPortPlaybook

This playbook responds to findings where a potentially sensitive port on an EC2 instance is left open to the internet and is being actively probed.

* **Registered Findings Include:**

| <mark style="color:$primary;">`Recon:EC2/PortProbeUnprotectedPort`</mark> | <mark style="color:$primary;">`Recon:EC2/PortProbeEMRUnprotectedPort`</mark> |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |

{% hint style="info" %}
A note on <mark style="color:$primary;">`Recon:EC2/PortProbeEMRUnprotectedPort`</mark> . This finding is the EC2 instance within an EMR cluster. Not an actual EMR cluster, so we handle it the same way as other EC2 instances with this finding.
{% endhint %}

* **Workflow**:
  1. **Tag Instance**: Applies tracking tags.
  2. **Enrich Finding**: Gathers live metadata.
  3. **Block Malicious IP**: Adds deny rules to the Network ACL for all probing IP addresses identified in the finding.
  4. **Remove Public Access (Optional)**: If <mark style="color:$primary;">`allow_remove_public_access`</mark> is <mark style="color:$primary;">`True`</mark>, this action removes any security group rules that allow unrestricted inbound access (i.e., from <mark style="color:$primary;">`0.0.0.0/0`</mark>).
* Key Configuration:
  * <mark style="color:$primary;">`allow_remove_public_access`</mark>: Controls whether the playbook is permitted to modify the instance's security groups. Disable this for instances that are intentionally public-facing (e.g., web servers).
