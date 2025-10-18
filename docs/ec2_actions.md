# EC2

## These actions interact with Amazon EC2 resources.

* **`BlockMaliciousIpAction`**: Adds inbound and outbound `deny` rules to the subnet's Network ACL (NACL) to block traffic from an attacker's IP address.
* **`CreateSnapshotAction`**: Creates snapshots of all EBS volumes attached to an instance for forensic preservation.
* **`EnrichFindingWithInstanceMetadataAction`**: Gathers live metadata (such as VPC ID and tags) from an EC2 instance to enrich the finding data.
* **`IsolateInstanceAction`**: Dynamically creates a new, empty security group and applies it to the instance, effectively removing it from the network.
* **`QuarantineInstanceProfileAction`**: Attaches a deny-all policy to the IAM role associated with an EC2 instance, revoking its AWS permissions.
* **`RemovePublicAccessAction`** (Optional): Removes public ingress rules (e.g., from `0.0.0.0/0`) from an instance's security groups. This is a potentially disruptive action controlled by the `allow_remove_public_access` configuration.
* **`TagInstanceAction`**: Applies a set of standardized tags to an EC2 instance for tracking and to indicate that a remediation is in progress.
* **`TerminateInstanceAction`** (Optional): Terminates a compromised EC2 instance. This is a destructive action controlled by the `allow_terminate` configuration.