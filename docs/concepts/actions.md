# 🔨 Actions

Actions are the fundamental building blocks of the GuardDuty-SOAR application. Each Action is an individual, reusable component that performs a single, discrete task, such as tagging a resource, creating a snapshot, or analyzing IAM permissions.

#### The Anatomy of an Action

Technically, an Action is a Python class that inherits from a common <mark style="color:$primary;">`BaseAction`</mark>. This structure ensures a consistent interface and behavior across the entire application.

* Initialization: Each Action is initialized with a <mark style="color:$primary;">`boto3.Session`</mark> and the application's <mark style="color:$primary;">`AppConfig`</mark>, giving it the context and credentials needed to interact with AWS services.
* Execution: The core logic resides in an <mark style="color:$primary;">`execute()`</mark> method. This method receives the GuardDuty finding and performs its specific task, often by making one or more calls to the AWS <mark style="color:$primary;">`boto3`</mark> SDK.
* Return Value: Every <mark style="color:$primary;">`execute()`</mark> method returns a consistent dictionary (<mark style="color:$primary;">`ActionResponse`</mark>) that reports the outcome of the operation. This standardized return format is crucial for the playbook to understand what happened.
  * Success: <mark style="color:$primary;">`{"status": "success", "details": "Descriptive message or data object."}`</mark>
  * Error: <mark style="color:$primary;">`{"status": "error", "details": "Detailed error message."}`</mark>&#x20;
  * Skipped: <mark style="color:$primary;">`{"status": "skipped", "details": "Action was skipped message."}`</mark>

#### The Role of Actions

This modular design provides several key architectural benefits:

* **Atomic Operations**: Each Action is responsible for one logical job. This makes the code easier to understand, debug, and maintain.
* **Reusability**: An Action can be used in multiple different playbooks. For example, the <mark style="color:$primary;">`TagInstanceAction`</mark> can be a step in a playbook for a brute-force attack, a credential exfiltration, or any other finding related to an EC2 instance.
* **Isolation and Testability**: Because each Action is a small, self-contained unit, it is easy to write focused and reliable unit tests for its specific functionality.

#### Actions vs. Playbooks

If a **Playbook** is a recipe for responding to a security event, then an **Action** is a single instruction in that recipe, like "chop the onions" or "preheat the oven." The Playbook orchestrates the overall workflow by calling a sequence of Actions, checking their results, and deciding what to do next.
