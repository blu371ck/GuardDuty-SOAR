# Plugin System Validation

## Objective
This scenario validates that the plugin system correctly discovers, loads, and prioritizes custom user-defined actions and playbooks. It specifically tests:
1.  **Playbook Override**: A custom playbook correctly overrides a built-in playbook for the same finding type.
2.  **New Playbook Discovery**: A custom playbook for a new, unregistered finding type is discovered and executed.
3.  **New Action Discovery**: A custom action is discovered and can be used by a custom playbook.

## Instructions

### 1. Create the Plugin Files
First, you need to create the custom plugin files. Place the following three files inside your project's `src/guardduty_soar/plugins/` directory, following the structure shown.

**File Structure:**
```
    src/ 
    └── guardduty_soar/ 
      └── plugins/ 
        ├── init.py 
        ├── actions/ 
        │ ├── init.py 
        │ └── simple_log_action.py <-- Create this file 
        └── playbooks/ 
          ├── init.py 
          ├── new_playbook.py <-- Create this file 
          └── override_playbook.py <-- Create this file
```
<details>
<summary>Click to see code for <code>plugins/actions/simple_log_action.py</code></summary>

```python
import logging
from guardduty_soar.actions.base import BaseAction
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)

class SimpleLogAction(BaseAction):
    """A simple custom action that logs a specific message."""
    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        message = kwargs.get("message_to_log", "No message provided.")
        logger.info(f"--- CUSTOM ACTION EXECUTED: {message} ---")
        return {"status": "success", "details": message}
```
</details>

<details> <summary>Click to see code for <code>plugins/playbooks/override_playbook.py</code></summary>

```Python
import logging
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.s3 import S3BasePlaybook
from guardduty_soar.models import PlaybookResult, GuardDutyEvent

logger = logging.getLogger(__name__)

# This registers for a finding type already handled by a built-in playbook.
@register_playbook("Discovery:S3/AnomalousBehavior")
class OverrideS3Playbook(S3BasePlaybook):
    """This custom playbook overrides the default S3CompromisedDiscoveryPlaybook."""
    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        logger.info("--- OVERRIDE PLAYBOOK IS RUNNING ---")
        # This playbook does nothing but log a message.
        return {"action_results": [], "enriched_data": {}}
```

</details>

<details> <summary>Click to see code for <code>plugins/playbooks/new_playbook.py</code></summary>

```Python

import logging
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.iam import IamBasePlaybook
from guardduty_soar.models import PlaybookResult, GuardDutyEvent
from plugins.actions.simple_log_action import SimpleLogAction # Import our custom action

logger = logging.getLogger(__name__)

# This registers a new playbook for a completely custom finding type.
@register_playbook("Custom:Test/PluginFinding")
class NewCustomPlaybook(IamBasePlaybook):
    """This is a brand new playbook that uses a custom action."""
    def __init__(self, config):
        super().__init__(config)
        self.simple_log_action = SimpleLogAction(self.session, self.config)

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        logger.info("--- NEW CUSTOM PLAYBOOK IS RUNNING ---")
        result = self.simple_log_action.execute(event, message_to_log="Testing custom action discovery.")
        return {"action_results": [result], "enriched_data": {}}
```
</details>

### 2. Create Test Event Files
Create the following two JSON files. These will be used to trigger the playbooks.

<details> <summary>Click to see code for <code>override_event.json</code></summary>

```JSON
{
    "detail": {
        "AccountId": "1234567891234",
        "Id": "override-test-finding",
        "Type": "Discovery:S3/AnomalousBehavior",
        "Description": "Test event to trigger the override playbook.",
        "Resource": {
            "ResourceType": "S3Bucket",
            "S3BucketDetails": [{"Name": "example-bucket"}]
        }
    }
}
```

</details>

<details> <summary>Click to see code for <code>new_event.json</code></summary>

```JSON
{
    "detail": {
        "AccountId": "1234567891234",
        "Id": "new-playbook-test-finding",
        "Type": "Custom:Test/PluginFinding",
        "Description": "Test event to trigger the new custom playbook.",
        "Resource": { "ResourceType": "Instance" }
    }
}
```

</details>

### 3. Run and Verify
From your project's root directory, you can now invoke the application locally for each event and check the logs to verify the plugin system is working.

#### Test 1: Verify the Override
```Bash
# Ensure your .env file is configured
uv run python -c "import json; from guardduty_soar.main import handler; handler(json.load(open('<YOUR_FULL_PATH_TO>\override_event.json')), {})"
```
Check the logs. You should see the message: --- OVERRIDE PLAYBOOK IS RUNNING ---. This confirms your custom playbook was loaded last and took precedence over the built-in one.

#### Test 2: Verify New Playbook and Action
```Bash
uv run python -c "import json; from guardduty_soar.main import handler; handler(json.load(open('<YOUR_FULL_PATH_TO>\new_event.json')), {})"
```
Check the logs. You should see the messages --- NEW CUSTOM PLAYBOOK IS RUNNING --- and --- CUSTOM ACTION EXECUTED: Testing custom action discovery. ---. This confirms the application discovered and ran a completely new playbook that successfully used a newly discovered custom action.