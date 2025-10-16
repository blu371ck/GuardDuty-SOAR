# EC2

## These actions interact with Amazon EC2 resources

* `BlockMaliciousIpAction`: Adds inbound and outbound `deny` rules to the appropriate Network ACL (NACL) to block traffic from an attacker's IP address.
* `EnrichFindingWithInstanceMetadataAction`: Gathers live metadata (such as VPC ID and tags) from an EC2 instance to enrich the finding data for notifications and subsequent actions.
* `IsolateInstanceAction`: Dynamically creates a new, deny-all security group in the instance's VPC and applies it, effectively removing the instance from the network for quarantine.
* `QuarantineInstanceProfileAction`: Attaches a deny-all policy (the AWS managed `AWSDenyAll` policy) to the IAM role associated with an EC2 instance, revoking its permissions to interact with other AWS services.
* `RemovePublicAccessAction`: Removes public ingress rules (e.g., from `0.0.0.0/0`) from an instance's security groups to mitigate exposure. This is a potentially disruptive action controlled by the `allow_remove_public_access` configuration.
* `CreateSnapshotAction`: Creates snapshots of all EBS volumes attached to an instance for forensic preservation and evidence collection.
* `TagInstanceAction`: Applies a set of standardized tags to an EC2 instance for tracking, visibility, and to indicate that a remediation process is underway.
* `TerminateInstanceAction`: Terminates a compromised EC2 instance. This is a destructive action controlled by the `allow_terminate` configuration.