import logging
from typing import List, Union

import boto3

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import (ActionResult, EnrichedEC2Finding,
                                   GuardDutyEvent)

# Import other notification actions here as you create them
# from guardduty_soar.actions.notifications.chatbot import SendChatbotNotificationAction

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    A manager class that orchestrates sending notifications to all configured
    and enabled channels.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        # Initialize all individual notification actions
        self.ses_action = SendSESNotificationAction(session, config)
        # self.chatbot_action = SendChatbotNotificationAction(session, config)
        # self.jira_action = ...

    def send_starting_notification(self, event: GuardDutyEvent, playbook_name: str):
        """Sends the initial notification that a playbook has started."""
        logger.info(f"Sending 'starting' notifications for playbook {playbook_name}.")
        # Call the execute method for each enabled notification action
        self.ses_action.execute(
            event, playbook_name=playbook_name, template_type="starting"
        )
        # self.chatbot_action.execute(...)

    def send_complete_notification(
        self,
        data: Union[GuardDutyEvent, EnrichedEC2Finding],
        playbook_name: str,
        action_results: List[ActionResult],
    ):
        """Sends the final, detailed notification when a playbook has finished."""
        logger.info(f"Sending 'complete' notifications for playbook {playbook_name}.")

        # Determine final status based on the action results
        if any(result["status"] == "error" for result in action_results):
            final_status_message = (
                f"PLAYBOOK FAILED: One or more actions were unsuccessful."
            )
            final_status_emoji = "❌"
        else:
            final_status_message = (
                "Playbook completed successfully. All actions were successful."
            )
            final_status_emoji = "✅"

        actions_summary = "\n".join(
            f"- {result.get('action_name', 'UnknownAction')}: {result['status'].upper()}"
            for result in action_results
        )

        # Call the execute method for each enabled notification action
        self.ses_action.execute(
            data,
            playbook_name=playbook_name,
            template_type="complete",
            final_status_emoji=final_status_emoji,
            actions_summary=actions_summary or "No actions were executed.",
            final_status_message=final_status_message,
        )
        # self.chatbot_action.execute(...)
