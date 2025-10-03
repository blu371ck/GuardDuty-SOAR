# Overview

GuardDuty SOAR is designed as a serverless, event-driven system that reacts to security findings in real-time. The architecture prioritizes speed, scalability, and low operational overhead by leveraging managed AWS services.

#### Event-Driven Flow

The entire workflow is initiated by an event and follows a clear, decoupled path from detection to response.

```
graph TD
    A[AWS GuardDuty] -- Detects Threat --> B(Amazon EventBridge);
    B -- Filters for GuardDuty Findings --> C{GuardDuty SOAR Lambda};
    C -- Parses Event & Gets Config --> D[Engine];
    D -- Finds Correct Playbook --> E[Playbook Registry];
    E -- Instantiates Playbook --> F[EC2 Compromise Playbook];
    F -- Executes Steps --> G((Actions));
    G -- Interact with AWS API --> H[Remediate AWS Resources];

```

1. **Detection:** **AWS GuardDuty** continuously monitors your AWS environment. When it detects a potential threat (e.g., a brute force attack against an EC2 instance), it generates a **Finding**.
2. **Routing:** Every GuardDuty Finding is automatically published as an event to the default **Amazon EventBridge** event bus in your account.
3. **Invocation:** An EventBridge Rule is configured to filter for specific GuardDuty findings. When a finding matches the rule, EventBridge invokes the **GuardDuty SOAR Lambda function**, passing the full finding JSON as the event payload.
4. **Orchestration:** The Lambda function handler (<mark style="color:$primary;">`main.py`</mark>) acts as the entry point. It initializes a central **Engine** object, injecting the finding details and application configuration (<mark style="color:$primary;">`gd.cfg`</mark>).
5. **Execution:** The Engine uses the finding type (e.g., <mark style="color:$primary;">`UnauthorizedAccess:EC2/TorClient`</mark>) to query the **Playbook Registry**. The registry returns an instance of the appropriate playbook (e.g., <mark style="color:$primary;">`EC2InstanceCompromisePlaybook`</mark>).
6. **Response:** The playbook's <mark style="color:$primary;">`run()`</mark> method is called. It executes a sequence of predefined **Actions** (e.g., <mark style="color:$primary;">`TagInstanceAction`</mark>, <mark style="color:$primary;">`IsolateInstanceAction`</mark>) in a specific order, using <mark style="color:$primary;">`boto3`</mark> to interact with the AWS API and remediate the threat.
