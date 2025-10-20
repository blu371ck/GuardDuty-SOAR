# 👋 Welcome to GuardDuty SOAR

**GuardDuty SOAR** is a fully serverless, event-driven SOAR (Security Orchestration, Automation, and Response) framework built on AWS. It transforms your AWS security posture from reactive to proactive by providing a robust, extensible, and cost-effective solution to automate the remediation of AWS GuardDuty findings in real-time.

When GuardDuty detects a potential threat, this framework instantly triggers a customizable **Playbook** via AWS EventBridge and Lambda. These playbooks execute a sequence of **Actions**—from tagging and isolating a compromised EC2 instance to blocking malicious IPs—all based on AWS security best practices. The result is a dramatic reduction in incident response time, a minimized blast radius for security events, and a consistent, auditable trail of all actions taken.

This project is not just a script; it's a production-ready framework designed for the realities of modern cloud security operations.

---
## Key Features

* **Serverless and Cost-Effective**: Built entirely on AWS Lambda, ensuring you only pay for what you use with zero idle costs.
* **Dynamic Playbook Engine**: A powerful, decorator-based registry allows you to add new remediation playbooks for any GuardDuty finding type without modifying the core engine.
* **Extensible via Plugins**: Add your own custom **Actions** and **Playbooks** to integrate with third-party tools (like Jira or Slack) or to override default remediation workflows. See the [Extending with Plugins](extending_with_plugins.md) guide for details.
* **Reusable Action Library**: Playbooks are composed of small, single-purpose **Actions** (e.g., `IsolateInstance`, `TagResource`) promoting clean, reusable code.
* **Layered & Decoupled Architecture**: A clean inheritance pattern separates orchestration (Playbooks) from implementation (Actions).
* **Comprehensive Testing Suite**: Includes a multi-layered testing strategy with isolated unit tests, integration tests against live AWS services, and full E2E validation scenarios.