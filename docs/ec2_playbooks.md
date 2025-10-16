# EC2

## EC2InstanceCompromisePlaybook

This is the most comprehensive and aggressive response playbook, designed for findings that strongly indicate an EC2 instance has been compromised. Its primary goal is to neutralize the threat and preserve evidence for forensic analysis.

* **Registered Findings Include**:

<table data-header-hidden data-full-width="false"><tbody><tr><td><code>Backdoor:EC2/*</code></td><td><code>Behavior:EC2/*</code></td><td><code>CryptoCurrency:EC2/*</code></td></tr><tr><td><code>DefenseEvasion:EC2/*</code></td><td><code>Impact:EC2/*</code></td><td><code>Recon:EC2/Portscan</code></td></tr><tr><td><code>Trojan:EC2/*</code></td><td><code>UnauthorizedAccess:EC2/MaliciousIPCaller.Customer</code></td><td><code>UnauthorizedAccess:EC2/TorClient</code></td></tr><tr><td><code>UnauthorizedAccess:EC2/TorRelay</code></td><td><code>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS</code></td><td><code>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS</code></td></tr></tbody></table>

!!! note
    A note on `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, these two findings are related to an EC2 instances profile becoming compromised. So, we run the** `EC2InstanceCompromisePlaybook` as it also places a deny-all policy on the instance profile, which will render the credentials useless.

* **Workflow**:
  1. **Tag Instance**: Applies tags to the instance for tracking (`SOAR-Status`, `GUARDDUTY-SOAR-I``D`, etc.).
  2. **Enrich Finding**: Gathers live metadata from the instance (VPC ID, security groups, etc.) to enrich the notification.
  3. **Isolate Instance**: Dynamically creates a new, deny-all security group in the instance's VPC and applies it, effectively taking the instance off the network.
  4. **Quarantine IAM Role**: Attaches the AWS managed `AWSDenyAll` policy to the instance's IAM role, revoking its permissions.
  5. **Create Snapshots**: Takes snapshots of all EBS volumes attached to the instance for forensic preservation.
  6. **Terminate Instance (Optional)**: If `allow_terminate` is `True` in the configuration, this action terminates the compromised instance.
* Key Configuration:
  * `allow_terminate`: Controls whether the playbook is permitted to terminate the instance.

## EC2BruteForcePlaybook

This playbook handles findings related to brute-force attacks and has two distinct response paths based on the role of the instance in the finding.

* **Registered Findings Include**:

<table data-header-hidden data-full-width="false"><tbody><tr><td><code>UnauthorizedAccess:EC2/RDPBruteForce</code></td><td><code>UnauthorizedAccess:EC2/SSHBruteForce</code></td></tr></tbody></table>

  * If the instance is the `TARGET` (i.e., it is being attacked):
    1. **Tag Instance**: Applies tracking tags to the instance.
    2. **Enrich Finding**: Gathers live metadata.
    3. **Block Malicious IP**: Adds deny rules to the subnet's Network ACL (NACL) to block the attacker's IP address.
  * If the instance is the `SOURCE` (i.e., it is performing the attack):
    * This indicates the instance is compromised. The playbook will execute the full `EC2InstanceCompromisePlaybook` workflow described above.

## EC2CredentialExfiltrationPlaybook

This playbook is triggered by findings that suggest IAM credentials may have been exfiltrated from an EC2 instance. The response is similar to a full compromise but is non-destructive by default.

* **Registered Findings Include:**

<table data-header-hidden data-full-width="false"><tbody><tr><td><code>UnauthorizedAccess:EC2/MetadataDNSRebind</code></td></tr></tbody></table>

* **Workflow**:
  1. **Tag Instance**: Applies tracking tags.
  2. **Enrich Finding**: Gathers live metadata.
  3. **Isolate Instance**: Dynamically creates and applies a deny-all security group.
  4. **Quarantine IAM Role**: Attaches the `AWSDenyAll` policy to the instance's IAM role.
  5. **Create Snapshots**: Takes snapshots of all attached EBS volumes.

!!! note
    This playbook intentionally does not terminate the instance, allowing an analyst to perform a live investigation.

## EC2UnprotectedPortPlaybook

This playbook responds to findings where a potentially sensitive port on an EC2 instance is left open to the internet and is being actively probed.

* **Registered Findings Include:**

<table data-header-hidden data-full-width="false"><tbody><tr><td><code>Recon:EC2/PortProbeUnprotectedPort</code></td><td><code>Recon:EC2/PortProbeEMRUnprotectedPort</code></td></tr></tbody></table>

!!! note 
    A note on `Recon:EC2/PortProbeEMRUnprotectedPort` . This finding is the EC2 instance within an EMR cluster. Not an actual EMR cluster, so we handle it the same way as other EC2 instances with this finding.

* **Workflow**:
  1. **Tag Instance**: Applies tracking tags.
  2. **Enrich Finding**: Gathers live metadata.
  3. **Block Malicious IP**: Adds deny rules to the Network ACL for all probing IP addresses identified in the finding.
  4. **Remove Public Access (Optional)**: If `allow_remove_public_access` is `True`, this action removes any security group rules that allow unrestricted inbound access (i.e., from `0.0.0.0/0`).
* Key Configuration:
  * `allow_remove_public_access`: Controls whether the playbook is permitted to modify the instance's security groups. Disable this for instances that are intentionally public-facing (e.g., web servers).