import logging
from typing import Any, Dict, List, Optional

import boto3

from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResult, GuardDutyEvent
from guardduty_soar.schemas import BaseResourceDetails, map_resource_to_model

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Orchestrates sending notifications to all configured and enabled channels.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        """Initializes all configured notification actions."""
        self.actions: List[BaseNotificationAction] = []
        if config.allow_ses:
            self.actions.append(SendSESNotificationAction(session, config))
        if config.allow_sns:
            self.actions.append(SendSNSNotificationAction(session, config))

    def _dispatch(self, **kwargs):
        """Helper to call execute on all registered actions."""
        for action in self.actions:
            try:
                action.execute(**kwargs)
            except Exception as e:
                logger.error(
                    f"Failed to execute notification action {type(action).__name__}: {e}."
                )

    def send_starting_notification(self, event: GuardDutyEvent, playbook_name: str):
        """Sends the initial notification that a playbook has started."""
        logger.info(
            f"Dispatching 'starting' notifications for playbook {playbook_name}."
        )

        resource_model = map_resource_to_model(event.get("Resource", {}))
        self._dispatch(
            finding=event,
            playbook_name=playbook_name,
            template_type="starting",
            resource=resource_model,
            enriched_data=None,
        )

    def send_complete_notification(
        self,
        finding: GuardDutyEvent,
        playbook_name: str,
        action_results: List[ActionResult],
        resource: BaseResourceDetails,
        enriched_data: Optional[Dict[str, Any]],
    ):
        """Sends the final, detailed notification when a playbook has finished."""
        logger.info(
            f"Dispatching 'complete' notifications for playbook {playbook_name}."
        )

        if any(result["status"] == "error" for result in action_results):
            final_status_message = (
                "PLAYBOOK FAILED: One or more actions were unsuccessful."
            )
            final_status_emoji = "❌"
        else:
            final_status_message = "Playbook completed successfully."
            final_status_emoji = "✅"

        actions_summary = (
            "\n".join(
                f"- {result.get('action_name', 'UnknownAction')}: {result['status'].upper()}"
                for result in action_results
            )
            or "No actions were executed."
        )

        self._dispatch(
            finding=finding,
            playbook_name=playbook_name,
            template_type="complete",
            resource=resource,
            enriched_data=enriched_data,
            final_status_emoji=final_status_emoji,
            actions_summary=actions_summary,
            final_status_message=final_status_message,
        )
