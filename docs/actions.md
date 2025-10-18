# 🔨 Actions

Actions are the fundamental building blocks of the GuardDuty-SOAR application. Each Action is an individual, reusable component that performs a single, discrete task, such as tagging a resource, creating a snapshot, or analyzing IAM permissions.

---
## The Anatomy of an Action

Technically, an Action is a Python class that inherits from a common `BaseAction`. This structure ensures a consistent interface and behavior across the entire application.

* **Initialization**: Each Action is initialized with a `boto3.Session` and the application's `AppConfig`, giving it the context and credentials needed to interact with AWS services.
* **Execution**: The core logic resides in an `execute()` method. This method receives the GuardDuty finding and performs its specific task, often by making one or more calls to the AWS `boto3` SDK.
* **Return Value**: Every `execute()` method returns a consistent dictionary (`ActionResponse`) that reports the outcome of the operation. This standardized return format is crucial for the playbook to understand what happened.
    * **Success**: `{"status": "success", "details": "Descriptive message or data object."}`
    * **Error**: `{"status": "error", "details": "Detailed error message."}`
    * **Skipped**: `{"status": "skipped", "details": "Reason why the action was skipped."}`

---
## The Role of Actions

This modular design provides several key architectural benefits:

* **Atomic Operations**: Each Action is responsible for one logical job. This makes the code easier to understand, debug, and maintain.
* **Reusability**: An Action can be used in multiple different playbooks. For example, the `TagInstanceAction` can be a step in a playbook for a brute-force attack, a credential exfiltration, or any other finding related to an EC2 instance.
* **Isolation and Testability**: Because each Action is a small, self-contained unit, it is easy to write focused and reliable unit tests for its specific functionality.

---
## Actions vs. Playbooks

If a **Playbook** is a recipe for responding to a security event, then an **Action** is a single instruction in that recipe, like "chop the onions" or "preheat the oven." The Playbook orchestrates the overall workflow by calling a sequence of Actions, checking their results, and deciding what to do next.