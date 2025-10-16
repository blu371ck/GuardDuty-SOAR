import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


# All actions have to execute something, but require some form of
# boto3 access as well as they need to know configurations.
class BaseAction(ABC):
    """
    Abstract base class for all playbook actions. Actions will cover a
    lot of similar functionality, however need to be handled differently
    based on the service and the GuardDuty event.

    :param boto3_session: a Boto3 Session object, used by inheriting classes
        to instantiate a Boto3 client.
    :param config: the inherited Application configuration.
    """

    def __init__(self, boto3_session: boto3.Session, config: AppConfig):
        self.session = boto3_session
        self.config = config

    def _calculate_severity(self, severity: float) -> str:
        """
        Simple function to take the numerical severity and return
        a more human-friendly label. Used in tagging for all the various
        AWS services. We define this here to keep inheriting classes DRY.

        :param severity: a float value retrieved from the GuardDuty event.
        :return: The string representation of that float values range. These
            value ranges are derived directly from AWS GuardDuty documentation.

        :meta private:
        """
        if 9.0 <= severity <= 10.0:
            return "CRITICAL"
        elif 7.0 <= severity <= 8.9:
            return "HIGH"
        elif 4.0 <= severity <= 6.9:
            return "MEDIUM"
        else:
            return "LOW"

    def _tags_to_apply(
        self, event: GuardDutyEvent, playbook_name: str
    ) -> List[Dict[str, Any]]:
        """
        This function produces the consistent tagging scheme we utilize when
        applying tags to objects in findings. Every playbook tags and they are
        not optional. We implement this here, to keep inheriting classes DRY.

        :param event: the GuardDutyEvent to parse and respond to.
        :param playbook_name: the Playbook classes name as a string.
        :return: a list object containing the boto3 API ready list of tags.

        :meta private:
        """
        return [
            {"Key": "GUARDDUTY-SOAR-ID", "Value": event["Id"]},
            {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"},
            {
                "Key": "SOAR-Action-Time-UTC",
                "Value": datetime.now(timezone.utc).isoformat(),
            },
            {"Key": "SOAR-Finding-Type", "Value": event["Type"]},
            {
                "Key": "SOAR-Finding-Severity",
                "Value": self._calculate_severity(float(event["Severity"])),
            },
            {"Key": "SOAR-Playbook", "Value": playbook_name},
        ]

    @abstractmethod
    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        This method is the invocation of all specific actions. It is inherited by all
        downstream classes, and is handled based on that actions service and specifics.

        :param event: the full GuardDuty event finding. The details are needed and handled
            differently based on the service and the finding.
        :return: An ActionResponse dictionary containing the status and details of the action.
        """
        raise NotImplementedError
