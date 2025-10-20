from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Sequence, cast

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

if TYPE_CHECKING:
    from mypy_boto3_ec2.type_defs import TagTypeDef

logger = logging.getLogger(__name__)


class TagInstanceAction(BaseAction):
    """
    An action to tag an EC2 instance. Indicating an event has occurred
    and provides visibility that the playbook has worked on that
    instance.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        # We only need to create the specific boto3 client once, for each
        # action. Creating a disposable client.
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")

        logger.warning(f"ACTION: Tagging instance: {instance_id}.")
        try:
            # We specifically have to enclose Sequence[TagTypeDef] in double-quotes because
            # this value is not covered by future's annotations, as its not evaluated till
            # runtime when needed.
            self.ec2_client.create_tags(
                Resources=[instance_id],
                Tags=cast(
                    "Sequence[TagTypeDef]", self._tags_to_apply(event, playbook_name)
                ),
            )
            details = f"Successfully added SOAR tags to instance: {instance_id}."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to add tags to instance: {instance_id}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            # Generic catch all
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
