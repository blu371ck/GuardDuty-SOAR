# EC2

## EC2InstanceCompromisePlaybook

This is the most comprehensive and aggressive response playbook, designed for findings that strongly indicate an EC2 instance has been compromised. Its primary goal is to neutralize the threat and preserve evidence for forensic analysis.

* **Registered Findings Include**:
    * `Backdoor:EC2/*`
    * `Behavior:EC2/*`
    * `CryptoCurrency:EC2/*`
    * `DefenseEvasion:EC2/*`
    * `Impact:EC2/*`
    * `Recon:EC2/Portscan`
    * `Trojan:EC2/*`
    * `UnauthorizedAccess:EC2/MaliciousIPCaller.Customer`
    * `UnauthorizedAccess:EC2/TorClient`
    * `UnauthorizedAccess:EC2/TorRelay`
    * `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
    * `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`

!!! note
    The `InstanceCredentialExfiltration` findings are related to an EC2 instance's profile becoming compromised. This playbook is used because its "Quarantine IAM Role" step places a deny-all policy on the instance profile, rendering the exfiltrated credentials useless.

* **Workflow**:
    1.  **Tag Instance**: Applies tracking tags to the instance for auditing.
    2.  **Enrich Finding**: Gathers live metadata from the instance (VPC ID, security groups, etc.).
    3.  **Isolate Instance**: Dynamically creates a new, empty security group and applies it to the instance, effectively taking it off the network.
    4.  **Quarantine IAM Role**: Attaches the `AWSDenyAll` policy to the instance's IAM role, revoking its permissions.
    5.  **Create Snapshots**: Takes snapshots of all EBS volumes attached to the instance for forensic preservation.
    6.  **Terminate Instance (Optional)**: If enabled, this action terminates the compromised instance.

* **Key Configurations**:
    * `allow_terminate`: If `true`, Step 6 will be executed. Defaults to `false`.

---

## EC2BruteForcePlaybook

This playbook handles findings related to brute-force attacks (`SSHBruteForce`, `RDPBruteForce`) and has two distinct response paths.

* **Registered Findings Include**:
    * `UnauthorizedAccess:EC2/RDPBruteForce`
    * `UnauthorizedAccess:EC2/SSHBruteForce`

* **Workflow**: The workflow depends on the instance's role in the finding:
    * **If the instance is the `TARGET`** (i.e., it is being attacked):
        1.  **Tag Instance**: Applies tracking tags to the instance.
        2.  **Enrich Finding**: Gathers live metadata.
        3.  **Block Malicious IP**: Adds a deny rule to the subnet's Network ACL (NACL) to block the attacker's IP address.
    * **If the instance is the `SOURCE`** (i.e., it is performing the attack):
        * This indicates the instance is compromised. The playbook will execute the full **`EC2InstanceCompromisePlaybook`** workflow described above.

---

## EC2CredentialExfiltrationPlaybook

This playbook is triggered by findings that suggest IAM credentials may have been exfiltrated from an EC2 instance. The response is similar to a full compromise but is non-destructive by default.

* **Registered Findings Include**:
    * `UnauthorizedAccess:EC2/MetadataDNSRebind`

* **Workflow**:
    1.  **Tag Instance**: Applies tracking tags.
    2.  **Enrich Finding**: Gathers live metadata.
    3.  **Isolate Instance**: Dynamically creates and applies a deny-all security group.
    4.  **Quarantine IAM Role**: Attaches the `AWSDenyAll` policy to the instance's IAM role.
    5.  **Create Snapshots**: Takes snapshots of all attached EBS volumes.

!!! note
    This playbook intentionally does not terminate the instance, allowing an analyst to perform a live investigation on the running system.

---

## EC2UnprotectedPortPlaybook

This playbook responds to findings where a potentially sensitive port on an EC2 instance is left open to the internet and is being actively probed.

* **Registered Findings Include**:
    * `Recon:EC2/PortProbeUnprotectedPort`
    * `Recon:EC2/PortProbeEMRUnprotectedPort`

!!! note
    The `PortProbeEMRUnprotectedPort` finding targets the EC2 instance within an EMR cluster, not the cluster itself, so it is handled like a standard EC2 instance.

* **Workflow**:
    1.  **Tag Instance**: Applies tracking tags.
    2.  **Enrich Finding**: Gathers live metadata.
    3.  **Block Malicious IP**: Adds deny rules to the Network ACL for all probing IP addresses identified in the finding.
    4.  **Remove Public Access (Optional)**: If enabled, this action removes any security group rules that allow unrestricted inbound access (i.e., from `0.0.0.0/0`).

* **Key Configurations**:
    * `allow_remove_public_access`: If `true`, Step 4 will be executed. Defaults to `false`. Disable this for instances that are intentionally public-facing (e.g., web servers).