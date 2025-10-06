# Playbook Engine Deep Dive

The core of the GuardDuty SOAR application is its flexible and extensible engine, which is built on three key architectural patterns: a dynamic registry, layered inheritance, and composition.

#### 1. The Playbook Registry (Decorator Pattern)

The system needs to map a GuardDuty finding type (a string) to the correct Python class that can handle it. Instead of a giant <mark style="color:$primary;">`if/elif/else`</mark> block or a hardcoded dictionary, we use a decorator-based registry.

* <mark style="color:$primary;">**`@register_playbook(...)`**</mark>: This decorator allows a playbook class to announce which finding types it can handle.
* <mark style="color:$primary;">**`_PLAYBOOK_REGISTRY`**</mark>: A private dictionary that stores the mapping of <mark style="color:$primary;">`finding_type -> PlaybookClass`</mark>.
* <mark style="color:$primary;">**`get_playbook_instance(...)`**</mark>: This factory function looks up the finding type in the registry and returns an initialized instance of the correct class.

This pattern makes the system **extensible**. To add a new playbook, you simply create a new class with the decorator; no changes are needed to the core engine.

#### 2. Layered Inheritance for Playbooks

To keep code DRY and organized, playbooks inherit from a series of base classes. Each layer adds a specific set of responsibilities.

```python
classDiagram
    class BasePlaybook {
        <<Abstract>>
        +session: boto3.Session
        +config: AppConfig
        +run(event)
    }

    class EC2BasePlaybook {
        <<Abstract>>
        +tag_instance: TagInstanceAction
        +isolate_instance: IsolateInstanceAction
        +_run_compromise_workflow()
    }

    class EC2InstanceCompromisePlaybook {
        +run(event)
    }
    
    class EC2BruteForcePlaybook {
        +run(event)
    }

    BasePlaybook <|-- EC2BasePlaybook
    EC2BasePlaybook <|-- EC2InstanceCompromisePlaybook
    EC2BasePlaybook <|-- EC2BruteForcePlaybook

```

* **`BasePlaybook`**: The "grandparent" class. It provides the universal components needed by _all_ playbooks: a <mark style="color:$primary;">`boto3`</mark> session and the application configuration. It defines an abstract <mark style="color:$primary;">`run()`</mark> method.
* **`EC2BasePlaybook`**: A service-specific "parent" class. It inherits from <mark style="color:$primary;">`BasePlaybook`</mark> and is responsible for initializing all the **Actions** related to EC2. It can also provide helper methods (like <mark style="color:$primary;">`_run_compromise_workflow`</mark>) for its children to use.
* **`EC2InstanceCompromisePlaybook`**: The final, concrete class. It inherits the tools from its parents and implements the <mark style="color:$primary;">`run()`</mark> method to define the specific sequence of steps for handling an incident.

#### 3. Composition for Actions

Playbooks themselves do not contain the logic for interacting with the AWS API. Instead, they are **composed** of smaller, reusable **Action** classes.

A playbook's <mark style="color:$primary;">`run()`</mark> method describes _what_ to do and in _what order_, while the action classes handle _how_ to do it.

```python
# Inside a Playbook's run() method:
def run(self, event: GuardDutyEvent):
    # Step 1: Tag the instance
    result = self.tag_instance.execute(event, ...)
    if result["status"] == "error":
        raise PlaybookActionFailedError(...)

    # Step 2: Isolate the instance
    result = self.isolate_instance.execute(event)
    if result["status"] == "error":
        raise PlaybookActionFailedError(...)

```

This **Composition over Inheritance** pattern makes the playbooks highly readable and makes the actions independently testable and reusable across multiple playbooks.
