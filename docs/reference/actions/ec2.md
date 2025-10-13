# EC2

## These actions interact with Amazon EC2 resources

* <mark style="color:$info;">`BlockMaliciousIpAction`</mark>: Adds inbound and outbound <mark style="color:$primary;">`deny`</mark> rules to the appropriate Network ACL (NACL) to block traffic from an attacker's IP address.
* <mark style="color:$info;">`EnrichFindingWithInstanceMetadataAction`</mark>: Gathers live metadata (such as VPC ID and tags) from an EC2 instance to enrich the finding data for notifications and subsequent actions.
* <mark style="color:$info;">`IsolateInstanceAction`</mark>: Dynamically creates a new, deny-all security group in the instance's VPC and applies it, effectively removing the instance from the network for quarantine.
* <mark style="color:$info;">`QuarantineInstanceProfileAction`</mark>: Attaches a deny-all policy (the AWS managed <mark style="color:$primary;">`AWSDenyAll`</mark> policy) to the IAM role associated with an EC2 instance, revoking its permissions to interact with other AWS services.
* <mark style="color:$info;">`RemovePublicAccessAction`</mark>: Removes public ingress rules (e.g., from <mark style="color:$primary;">`0.0.0.0/0`</mark>) from an instance's security groups to mitigate exposure. This is a potentially disruptive action controlled by the <mark style="color:$primary;">`allow_remove_public_access`</mark> configuration.
* <mark style="color:$info;">`CreateSnapshotAction`</mark>: Creates snapshots of all EBS volumes attached to an instance for forensic preservation and evidence collection.
* <mark style="color:$info;">`TagInstanceAction`</mark>: Applies a set of standardized tags to an EC2 instance for tracking, visibility, and to indicate that a remediation process is underway.
* <mark style="color:$info;">`TerminateInstanceAction`</mark>: Terminates a compromised EC2 instance. This is a destructive action controlled by the <mark style="color:$primary;">`allow_terminate`</mark> configuration.
