![guardduty_image](./images/guardduty_soar_logo.png)

![Static Badge](https://img.shields.io/badge/Alpha-BBB?style=plastic&label=Dev%20Stage)
![Static Badge](https://img.shields.io/badge/Python-3.13-BBB?logo=python&logoColor=fff)
![isort](https://img.shields.io/badge/%20Import_Style-isort-BBB?style=plastic&logo=Python&logoColor=FFFFFF)
![Static Badge](https://img.shields.io/badge/Typed-mypy-BBB?style=plastic&logo=python&logoColor=FFFFFF)
![black](https://img.shields.io/badge/Black-BBB?style=plastic&logo=black&logoColor=FFFFFF)
![Static Badge](https://img.shields.io/badge/pytest-BBB?style=plastic&logo=pytest&logoColor=FFFFFF)
![UV](https://img.shields.io/badge/uv-BBB?style=plastic&logo=uv&logoColor=FFFFFF)
![AWS](https://custom-icon-badges.demolab.com/badge/AWS-BBB.svg?logo=aws&logoColor=FFFFFF)
[![Documentation](https://img.shields.io/badge/Documentation-MkDocs-FFFFFF?style=plastic)](https://docs.guardduty-soar.com)

**GuardDuty SOAR** is a fully serverless, event-driven SOAR (Security Orchestration, Automation, and Response) framework built on AWS. It transforms your AWS security posture from reactive to proactive by providing a robust, extensible, and cost-effective solution to automate the remediation of AWS GuardDuty findings in real-time.

When GuardDuty detects a potential threat, this framework instantly triggers a customizable **Playbook** via AWS EventBridge and Lambda. These playbooks execute a sequence of **Actions**—from tagging and isolating a compromised EC2 instance to blocking malicious IPs—all based on AWS security best practices. The result is a dramatic reduction in incident response time, a minimized blast radius for security events, and a consistent, auditable trail of all actions taken.

This project is not just a script; it's a production-ready framework designed for the realities of modern cloud security operations.

---
## Key Features

* **Serverless and Cost-Effective**: Built entirely on AWS Lambda, ensuring you only pay for what you use with zero idle costs.
* **Dynamic Playbook Engine**: A powerful, decorator-based registry allows you to add new remediation playbooks for any GuardDuty finding type without modifying the core engine.
* **Extensible via Plugins**: Add your own custom **Actions** and **Playbooks** to integrate with third-party tools (like Jira or Slack) or to override default remediation workflows. See the [Extending with Plugins](https://docs.guardduty-soar.com/extending_with_plugins/) guide for details.
* **Reusable Action Library**: Playbooks are composed of small, single-purpose **Actions** (e.g., `IsolateInstance`, `TagResource`) promoting clean, reusable code.
* **Layered & Decoupled Architecture**: A clean inheritance pattern separates orchestration (Playbooks) from implementation (Actions).
* **Comprehensive Testing Suite**: Includes a multi-layered testing strategy with isolated unit tests, integration tests against live AWS services, and full E2E validation scenarios.

## Project Roadmap & Status

This project is developed in stages. Here is a high-level overview of our progress.

| Alpha | Beta | Maintenance |
| :--- | :--- | :--- |
| **Tasks:** Playbook and Action Creation | **Tasks:** Refactoring, Live Testing and Bug Fixes | **Tasks:** Issues, Documentation and Enhancements |
| ✅ EC2 Findings | ☐ Code refactoring (where applicable) | ☐ Reported Issues |
| ✅ IAM Findings | ☐ Test refactoring (where applicable) | ☐ Documentation refactoring and updating |
| ✅ Live Terraform Testing | ☐ Bug Fixes (Continuous) | ☐ Feature request enhancements |
| ✅ Documentation Rough |☐ Light Enhancements | ☐ Bug Fixes (Continuous)
| ✅ S3 Protection Findings |  |  |
| ☐ RDS Protection Findings |  | |
| ☐ Lambda Protection Findings |  | |
| ☐ EKS Protection Findings |  |  |
| ☐ Malware Protection for EC2 Findings | | |
| ☐ Malware Protection for S3 Findings | | |
| ☐ Runtime Monitoring Findings | | |
| ☐ Attack Sequence Findings   | | |

## Documentation

[![Documentation](https://img.shields.io/badge/Documentation-MkDocs-4785FF?style=for-the-badge)](https://docs.guardduty-soar.com)
