# 📣 Notifications

The notification system provides real-time visibility into the GuardDuty-SOAR application's operations. It is designed to support two distinct use cases: immediate human awareness and automated downstream integration. This is achieved through two configurable AWS service channels: Amazon SES and Amazon SNS.

#### Notification Channels

You can enable one or both of the following channels in your configuration.

**Amazon SES (Simple Email Service)**

* **Purpose**: Human-Readable Alerts
* **Use Case**: Sending detailed, richly formatted email notifications directly to security analysts, response teams, or distribution lists. The format is optimized for quick human comprehension, providing all necessary context to understand the finding and the actions taken.

**Amazon SNS (Simple Notification Service)**

* **Purpose**: Machine-Readable Alerts
* **Use Case**: Publishing structured JSON messages to an SNS topic. This is ideal for programmatic integration with other systems. For example, you can subscribe another AWS Lambda function to this topic to forward alerts to a SIEM, a ticketing system (like Jira or ServiceNow), or a chat application (like Slack or Microsoft Teams).

#### Notification Types

The system dispatches two types of notifications during a playbook's lifecycle:

1. <mark style="color:$primary;">`playbook_started`</mark>: A brief notification sent the moment a playbook begins execution. It contains the initial details of the GuardDuty finding and confirms that an automated response is underway.
2. <mark style="color:$primary;">`playbook_completed`</mark>: A comprehensive report sent after a playbook finishes. This message includes the final status of the playbook (success or failure), a summary of every action performed, and all enriched data gathered during the investigation (e.g., instance metadata, IAM policy analysis, CloudTrail history).

***

#### Message Formats

Each channel uses a different template format, tailored to its specific purpose.

**SES Format (Markdown/HTML)**

SES notifications are generated from Markdown templates (files ending in <mark style="color:$primary;">`.md.j2`</mark>). This allows for easy-to-read text formatting that is also highly extensible.

* **Structure**: Each template begins with a <mark style="color:$primary;">`Subject:`</mark> line, which is extracted to become the email's subject. The rest of the file forms the body of the message.
* **Conversion**: The application automatically converts the Markdown body into HTML. The final email is sent as a multi-part message containing both the plain text and HTML versions, ensuring compatibility and readability across all modern email clients.

**SNS Format (JSON)**

SNS notifications are generated from JSON templates (files ending in <mark style="color:$primary;">`.json.j2`</mark>) to provide structured data for automation. The message is published with <mark style="color:$primary;">`MessageStructure="raw"`</mark>, meaning the exact JSON you define is what subscribers receive.

Below is an example of a <mark style="color:$primary;">`playbook_completed`</mark> JSON notification:

```json
{
  // The type of notification event
  "event_type": "playbook_completed",
  // The name of the playbook that was executed
  "playbook_name": "IamForensicsPlaybook",
  // An emoji indicating the final status
  "status_emoji": "✅",
  // A human-readable summary of the final status
  "status_message": "Playbook completed successfully.",
  // A summary of each action taken and its result
  "actions_summary": "- IdentifyPrincipal: SUCCESS; - TagPrincipal: SUCCESS; ...",
  // Key details from the original GuardDuty finding
  "finding": {
    "id": "iam-finding-id",
    "type": "CredentialAccess:IAMUser/AnomalousBehavior"
  },
  // The Pydantic model of the affected resource from the finding
  "resource": {
    "resource_type": "AccessKey",
    "access_key_id": "ASIA_TEST_KEY",
    "user_name": "gd-soar-risky-user-..."
  },
  // A rich object containing all data gathered by the playbook's actions
  "enriched_data": {
    "details": {
      "UserName": "gd-soar-risky-user-...",
      "Arn": "arn:aws:iam::...",
      "CreateDate": "2025-10-11T13:11:26Z"
    },
    "attached_policies": [],
    "permission_analysis": {
      "risks_found": {
        "InlinePolicy: gd-soar-risky-inline-policy": [
          "Allows all actions ('*') on all resources ('*')."
        ]
      }
    }
  }
}
```
