import logging
from typing import Callable, Dict, Type

import boto3

from guardduty_soar.models import GuardDutyEvent

logger = logging.getLogger(__name__)

_PLAYBOOK_REGISTRY: Dict[str, Type["BasePlaybook"]] = {}


def register_playbook(*finding_types: str) -> Callable:
    """
    A decorator that registers playbook classes for specific GuardDuty
    finding types.
    """

    def decorator(cls: Type["BasePlaybook"]) -> Type["BasePlaybook"]:
        for finding_type in finding_types:
            logger.info(f"Registering playbook for finding: {finding_type}")
            _PLAYBOOK_REGISTRY[finding_type] = cls
        return cls

    return decorator


def get_playbook_instance(finding_type: str) -> "BasePlaybook":
    """
    Looks up a finding type and returns an 'instance' of the corresponding
    playbook class.
    """
    playbook_class = _PLAYBOOK_REGISTRY.get(finding_type)
    if not playbook_class:
        raise ValueError(f"No playbook registered for finding type: {finding_type}.")

    logger.info(f"Found playbook: '{str(playbook_class)}'.")
    return playbook_class()


class BasePlaybook:
    """
    All playbooks should inherit from this class.
    """

    def __init__(self):
        # Creates a single session for the playbook.
        self.session = boto3.Session()

    def run(self, event: GuardDutyEvent):
        raise NotImplementedError
