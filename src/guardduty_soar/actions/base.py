import logging
from abc import ABC, abstractmethod

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


# All actions have to execute something, but require some form of
# boto3 access as well as they need to know configurations.
class BaseAction(ABC):
    """
    Abstract base class for all remediation actions.
    """

    def __init__(self, boto3_session: boto3.Session, config: AppConfig):
        self.session = boto3_session
        self.config = config

    @abstractmethod
    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Executes the remediation action.

        Args:
            event: The full GuardDuty finding detail dictionary.
            **kwargs: Optional keyword arguments for actions that need extra context.

        Returns:
            An ActionResponse dictionary containing the status and details of the action.
        """
        raise NotImplementedError
