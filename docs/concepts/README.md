# 🏛️ Concepts

This document provides a high-level overview of the core architectural concepts of the GuardDuty-SOAR application. Understanding how these components interact is key to customizing behavior and extending the application with new functionality.

The application is built around three main concepts:

* [**Configurations**](configurations.md): Defines the application's runtime behavior, allowing you to enable or disable features, set parameters for actions, and configure notifications without changing the code.
* [**Playbooks**](playbooks.md): High-level workflows that orchestrate the response to specific GuardDuty findings. Each playbook is a sequence of actions designed to investigate and remediate a particular threat.
* [**Actions**](actions.md): The individual, reusable building blocks of a playbook. An action performs a single, discrete task, such as tagging a resource, creating a snapshot, or analyzing IAM permissions.

