# 📑 Playbooks

A **Playbook** is an automated workflow that orchestrates the response to a specific GuardDuty finding, or a group of related findings. Think of it as the strategic "recipe" for handling a security event, where each step in the recipe is an **Action**.

#### The Anatomy of a Playbook

In the GuardDuty-SOAR application, a Playbook is a Python class with a defined structure:

* **Inheritance**: Each Playbook inherits from a base class (e.g., <mark style="color:$primary;">`EC2BasePlaybook`</mark>, <mark style="color:$primary;">`IamBasePlaybook`</mark>) which provides it with a set of pre-initialized, relevant Actions.
* Decorator Registration: A Playbook is registered to handle one or more GuardDuty finding types using the <mark style="color:$primary;">`@register_playbook(...)`</mark> decorator. This allows the application's engine to automatically select the correct Playbook when a finding is received.

{% hint style="info" %}
We will eventually add the ability to add new actions and playbooks into a plugins directory. This functionality will be directly possible because of the registration decorator. Allowing end-users to create fully customizable playbooks using pre-built actions, or their own action logic. (This functionality is on the schedule to be worked on after all base items have been covered.)
{% endhint %}

* Execution Logic: The core logic resides in a <mark style="color:$primary;">`run()`</mark> method. This method defines the sequence of Actions to be executed, handles their results, and aggregates data.
* Return Value: Upon completion, the <mark style="color:$primary;">`run()`</mark> method returns a <mark style="color:$primary;">`PlaybookResult`</mark> dictionary, which contains the results of all executed actions and any data that was gathered for enrichment.

#### The Role of Playbooks

Playbooks are the brains of the remediation process, responsible for:

* **Orchestration**: Defining the precise sequence of Actions that constitute the response for a given threat.
* **Control Flow**: Checking the <mark style="color:$primary;">`status`</mark> of each Action's result and making decisions, such as halting execution by raising a <mark style="color:$primary;">`PlaybookActionFailedError`</mark> if a critical step fails.
* **Data Management**: Passing context and data between Actions. For example, a playbook might use the output from an <mark style="color:$primary;">`IdentifyPrincipalAction`</mark> as the input for a <mark style="color:$primary;">`TagPrincipalAction`</mark>.
