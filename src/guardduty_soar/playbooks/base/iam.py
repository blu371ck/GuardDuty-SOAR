import logging

from guardduty_soar.config import AppConfig
from guardduty_soar.playbook_registry import BasePlaybook

logger = logging.getLogger(__name__)


class IamForensicsPlaybook(BasePlaybook):
    """
    An intermediate base class for all playbooks that respond to IAM findings.
    (Minus two that belong to ec2 credential theft, which are in
    EC2InstanceCompromisePlaybook).

    Inherits the boto3 session from BasePlaybook and initializes all relevant IAM
    action classes.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config)
        # For each child of the BasePlaybook class we will register all actions
        # applicable to all playbooks regarding that type. This allows them
        # to be used by children without needing to import the code in multiple
        # places.
