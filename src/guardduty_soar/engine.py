import logging
from datetime import datetime
from typing import List, cast

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, EnrichedEC2Finding, GuardDutyEvent
from guardduty_soar.notifications.manager import NotificationManager
from guardduty_soar.playbook_registry import get_playbook_instance

logger = logging.getLogger(__name__)


class Engine:
    """
    Class that handles parsing and direction of GuardDuty event
    findings.

    Parameters:
        event: Dict of 'strictly' GuardDuty's event finding.
    Returns:
        None
    """

    def __init__(self, event: GuardDutyEvent, config: AppConfig) -> None:
        required_keys = ["Type", "Id", "Description"]
        if not all(key in event for key in required_keys):
            # TODO We only check for these items, as (so far) these are the only items we
            # need at this stage will add more as more actions require more and more
            # of the original event.
            raise ValueError(
                "Event not complete. Missing one of: 'Type', 'Id', 'Description'."
            )

        # Store the event in 'self', making the pointer accessible to all class
        # methods.
        self.event = event
        self.config = config
        self.session = boto3.Session()
        self.notification_manager = NotificationManager(self.session, self.config)

        logger.debug(f"Initialized with config: {self.config}")

        logger.info(
            f"Incoming GuardDuty event with id: '{self.event['Id']}'. Starting processing at: '{datetime.now()}'."
        )
        logger.info(f"Description: '{self.event['Description']}'.")

    def handle_finding(self) -> None:
        """
        Handles the lookup and use of the appropriate playbook for the
        finding type.
        """
        playbook = None
        playbook_name = "UnknownPlaybook"
        action_results: List[ActionResult] = []
        enriched_data = None

        logger.info(f"Starting lookup for type: '{self.event['Type']}'.")
        try:
            playbook = get_playbook_instance(self.event["Type"], self.config)
            playbook_name = playbook.__class__.__name__

            # Send starting notifications
            self.notification_manager.send_starting_notification(
                self.event, playbook_name
            )
            playbook_result = playbook.run(self.event)
            action_results = playbook_result["action_results"]
            enriched_data = playbook_result["enriched_data"]

        # TODO Currently raising an exception for not having a playbook found.
        # Will later be adding functionality to allow end-users to pick
        # and choose which alerts trigger, making it no longer a valid
        # exception.
        except (ValueError, PlaybookActionFailedError) as e:
            logger.critical(f"Playbook execution failed for {playbook_name}: {e}.")
            # Add the failure to the results for the final report.
            action_results.append(
                {
                    "status": "error",
                    "details": str(e),
                    "action_name": "PlaybookExecution",
                }
            )

        finally:
            # This block is guaranteed to send a final notification regardless of outcome
            final_notification_data = (
                cast(EnrichedEC2Finding, enriched_data) if enriched_data else self.event
            )

            self.notification_manager.send_complete_notification(
                data=final_notification_data,
                playbook_name=playbook_name,
                action_results=action_results,
            )
