# 📑 Playbooks

The following sections provide a detailed reference for all playbooks currently built into GuardDuty-SOAR.

Each playbook is designed to respond to a specific category of threat and can be registered to handle multiple, related GuardDuty finding types. As a result, there is not always a one-to-one relationship between a finding and a playbook.

Playbooks are organized by the primary AWS service they target:

* [**EC2**](ec2.md): Workflows that respond to threats originating from or targeting EC2 instances, such as brute-force attacks or instance compromises.
* [**IAM**](iam.md): Workflows focused on forensic analysis of findings related to IAM principals (users and roles), such as anomalous API activity.

