import logging
from datetime import datetime

from guardduty_soar.models import GuardDutyEvent
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

    def __init__(self, event: GuardDutyEvent) -> None:
        required_keys = ["Type", "Id", "Description"]
        if not all(key in event for key in required_keys):
            raise ValueError(
                "Event not complete. Missing one of: 'Type', 'Id', 'Description'."
            )

        self.event = event
        logger.info(
            f"Incoming GuardDuty event with id: '{self.event['Id']}'. Starting processing at: '{datetime.now()}'."
        )
        logger.info(f"Description: '{self.event['Description']}'.")

    def handle_finding(self) -> None:
        """
        Handles the lookup and use of the appropriate playbook for the
        finding type.
        """
        logger.info(f"Starting lookup for type: '{self.event['Type']}'.")
        try:
            playbook = get_playbook_instance(self.event["Type"])
            playbook.run(self.event)
        except ValueError as e:
            logger.critical(
                f"No playbook registered for finding type: {self.event['Type']}."
            )
