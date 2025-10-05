import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResult, GuardDutyEvent

logger = logging.getLogger(__name__)

_PLAYBOOK_REGISTRY: Dict[str, Type["BasePlaybook"]] = {}


def register_playbook(*finding_types: str) -> Callable:
    """
    A decorator that registers playbook classes for specific GuardDuty
    finding types.
    """

    def decorator(cls: Type["BasePlaybook"]) -> Type["BasePlaybook"]:
        for finding_type in finding_types:
            logger.debug(f"Registering playbook for finding: {finding_type}")
            _PLAYBOOK_REGISTRY[finding_type] = cls
        return cls

    return decorator


def get_playbook_instance(finding_type: str, config: AppConfig) -> "BasePlaybook":
    """
    Looks up a finding type and returns an 'instance' of the corresponding
    playbook class.
    """
    playbook_class = _PLAYBOOK_REGISTRY.get(finding_type)
    if not playbook_class:
        raise ValueError(f"No playbook registered for finding type: {finding_type}.")

    logger.info(f"Found playbook: '{str(playbook_class)}'.")
    return playbook_class(config)


class BasePlaybook:
    """
    All playbooks should inherit from this class.
    """

    def __init__(self, config: AppConfig):
        # Creates a single session for the playbook.
        self.config = config
        self.session = boto3.Session()

    def run(
        self, event: GuardDutyEvent
    ) -> Tuple[List[ActionResult], Optional[Dict[str, Any]]]:
        raise NotImplementedError
