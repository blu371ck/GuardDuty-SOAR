import logging
from datetime import datetime

from guardduty_soar.config import AppConfig
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
        logger.info(f"Starting lookup for type: '{self.event['Type']}'.")
        try:
            playbook = get_playbook_instance(self.event["Type"], self.config)
            playbook.run(self.event)
        # TODO Currently raising an exception for not having a playbook found.
        # Will later be adding functionality to allow end-users to pick
        # and choose which alerts trigger, making it no longer a valid
        # exception.
        except ValueError as e:
            logger.critical(
                f"No playbook registered for finding type: {self.event['Type']}."
            )
