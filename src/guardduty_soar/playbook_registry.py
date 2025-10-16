import logging
from typing import Callable, Dict, Type

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.models import GuardDutyEvent, PlaybookResult

logger = logging.getLogger(__name__)

_PLAYBOOK_REGISTRY: Dict[str, Type["BasePlaybook"]] = {}


def register_playbook(*finding_types: str) -> Callable:
    """
    A decorator that registers playbook classes for specific GuardDuty
    finding types. These decorators are used to dynamically load
    the playbook classes as well as finding the appropriate playbook
    based on the GuardDuty's finding type.

    :param finding_types: any number of strings representing finding types. Some
        playbooks will register more than one finding type. We need to iterate
        over them all and register them all, ensuring they all point to the same
        playbook.
    :return: A Python callable
    """

    def decorator(cls: Type["BasePlaybook"]) -> Type["BasePlaybook"]:
        for finding_type in finding_types:
            logger.debug(f"Registering playbook for finding: {finding_type}")
            _PLAYBOOK_REGISTRY[finding_type] = cls
        return cls

    return decorator


class BasePlaybook:
    """
    The base class for all playbooks. All playbooks inherit this class,
    and can extend it based on the service the playbook is working on.

    :param config: an AppConfig object that is ingested so that inheriting
        classes have direct access to its data.
    """

    def __init__(self, config: AppConfig):
        # Creates a single session for the playbook.
        self.config = config
        self.session = boto3.Session()

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        """
        The run method is responsible for all Action's being invoked in a
        specific order. All classes inherit this method, and provide their
        own set of Actions, based on their GuardDuty finding type.

        :param event: the GuardDutyEvent object passed in with the Lambda event
            json.
        :return: A PlaybookResult object, which is a List[ActionResults] and
            an optional dictionary object.
        """
        raise NotImplementedError


def get_playbook_instance(finding_type: str, config: AppConfig) -> BasePlaybook:
    """
    Looks up a finding type and returns an 'instance' of the corresponding
    playbook class.
    """
    playbook_class = _PLAYBOOK_REGISTRY.get(finding_type)
    if not playbook_class:
        raise ValueError(f"No playbook registered for finding type: {finding_type}.")

    logger.info(f"Found playbook: '{playbook_class.__name__}'.")
    return playbook_class(config)
