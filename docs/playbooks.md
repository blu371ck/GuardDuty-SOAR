# 📑 Playbooks

A **Playbook** is an automated workflow that orchestrates the response to a specific GuardDuty finding or a group of related findings. It is the strategic "recipe" for handling a security event, where each step in the recipe is an **Action**.

---
## The Anatomy of a Playbook

In the GuardDuty-SOAR application, a Playbook is a Python class with a defined structure:

* **Registration**: A Playbook is registered to handle one or more GuardDuty finding types using the `@register_playbook(...)` decorator. This allows the application's engine to automatically select the correct Playbook when a finding is received.
* **Inheritance**: Each Playbook inherits from a base class (e.g., `EC2BasePlaybook`, `S3BasePlaybook`) which provides it with a set of pre-initialized, relevant Actions. Playbooks can also inherit from other playbooks to reuse and extend common workflows.
* **Execution Logic**: The core logic resides in a `run()` method. This method defines the sequence of Actions to be executed, handles their results, and aggregates data.
* **Return Value**: Upon completion, the `run()` method returns a `PlaybookResult` dictionary, containing the results of all executed actions and any enriched data.

!!! note
    The registration decorator is designed to eventually support a plugins directory, allowing you to create fully custom playbooks using pre-built or custom actions without modifying the core application code.

---
## The Role of Playbooks

Playbooks are the brains of the remediation process, responsible for:

* **Orchestration**: Defining the precise sequence of Actions that constitute the response for a given threat.
* **Control Flow**: Checking the `status` of each Action's result and making decisions, such as halting execution if a critical step fails.
* **Data Management**: Passing context and data between Actions. For example, a playbook will use the output from an `IdentifyPrincipalAction` as the input for a `TagPrincipalAction`.