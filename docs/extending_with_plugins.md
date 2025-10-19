# 🧩 Extending with Plugins

The GuardDuty-SOAR application is built on an extensible plugin system that allows you to add your own custom logic without modifying the core source code. You can create new **Actions** to integrate with third-party systems (like Jira or Slack) and new **Playbooks** to define custom workflows for responding to GuardDuty findings.

This system provides two key capabilities:

* **Extensibility**: Add new functionality to the application.
* **Customizability**: Override the default, built-in playbooks with your own preferred logic.

---
## Directory Structure

The plugin system is powered by a `plugins` directory located within the main application package. The application will automatically discover and load any Python modules you add to the `actions` and `playbooks` subdirectories.

```
src/ 
└── guardduty_soar/ 
   ├── init.py 
   ├── main.py 
   ├── actions/ 
   ├── playbooks/ 
   └── plugins/ <-- Your custom code goes here 
      ├── init.py 
      ├── actions/ 
      │ ├── init.py 
      │ └── custom_action.py.example 
      └── playbooks/ 
        ├── init.py 
        └── custom_playbook.py.example
```
!!! note
    We provide `.example` files as templates. To activate a plugin, simply copy the example file and rename it to end in `.py`.

---
## Creating a Custom Action

An Action is a class that performs a single, discrete task. To create your own, you'll create a new `.py` file in the `plugins/actions/` directory.

**Anatomy of a Custom Action:**

1.  It must inherit from `guardduty_soar.actions.base.BaseAction`.
2.  The core logic must be implemented in an `execute()` method.
3.  The `execute()` method must return a dictionary with a `status` and `details`.

#### Example: `plugins/actions/log_message_action.py`
```python
import logging
from typing import ActionResponse, GuardDutyEvent

from guardduty_soar.actions.base import BaseAction

logger = logging.getLogger(__name__)

class LogMessageAction(BaseAction):
    """
    A simple custom action that logs a specific message.
    """
    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        # You can get custom arguments from the kwargs passed by the playbook.
        message = kwargs.get("message_to_log", "No message provided.")
        finding_id = event.get("Id", "UnknownId")

        details = f"Custom action was called for finding {finding_id}: {message}"
        logger.info(f"ACTION: {details}")

        # All actions must return a status and details.
        return {"status": "success", "details": details}
```
### Creating a Custom Playbook
A Playbook orchestrates one or more Actions. To create a custom playbook, you'll add a new .py file to the plugins/playbooks/ directory.

#### Anatomy of a Custom Playbook:
1. It must inherit from one of the base playbooks (e.g., S3BasePlaybook, EC2BasePlaybook, IamBasePlaybook) to gain access to the built-in actions for that service.
2. It must use the @register_playbook() decorator to tell the engine which GuardDuty finding(s) it should handle.
3. The workflow logic is defined in the run() method.

**Example**: `plugins/playbooks/my_forensics_playbook.py`
This example creates a simple playbook that uses a built-in action and our new custom action.
```Python
import logging
from typing import PlaybookResult, GuardDutyEvent

from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.iam import IamBasePlaybook
from plugins.actions.log_message_action import LogMessageAction # Import your custom action

logger = logging.getLogger(__name__)

@register_playbook("Recon:IAMUser/UserPermissions")
class MyForensicsPlaybook(IamBasePlaybook):
    """
    A custom playbook that runs for a specific Recon finding.
    """
    def __init__(self, config):
        super().__init__(config)
        # Initialize your custom action
        self.log_message = LogMessageAction(self.session, self.config)

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        logger.info("Executing MyForensicsPlaybook...")
        
        # Step 1: Use a built-in action from the IamBasePlaybook
        identity_result = self.identify_principal.execute(event)
        
        # Step 2: Use our custom action
        log_result = self.log_message.execute(
            event, message_to_log="IAM forensics has started."
        )

        return {
            "action_results": [
                {**identity_result, "action_name": "IdentifyIamPrincipal"},
                {**log_result, "action_name": "LogMessage"},
            ],
            "enriched_data": {}
        }
```

---
## Overriding a Built-in Playbook
The plugin system automatically handles overrides. If you register a custom playbook for a finding type that is already handled by a built-in playbook, your custom playbook will be used instead.

This allows you to completely replace the default behavior for any finding.

### Example: Disabling a Response
To effectively disable a response for a finding without adding it to ignored_findings, you can register a "do-nothing" playbook.

```Python
# in plugins/playbooks/override_playbook.py
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

# This finding is normally handled by EC2InstanceCompromisePlaybook.
# Now, this empty playbook will run instead.
@register_playbook("Backdoor:EC2/Spambot")
class DoNothingPlaybook(EC2BasePlaybook):
    def run(self, event):
        # This playbook does nothing and returns an empty result.
        return {"action_results": [], "enriched_data": {}}
```