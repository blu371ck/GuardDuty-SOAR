from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List, cast

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

if TYPE_CHECKING:
    from mypy_boto3_rds.type_defs import TagTypeDef


logger = logging.getLogger(__name__)


class TagRdsInstanceAction(BaseAction):
    """
    This action tags an RDS instance to signify that the GuardDuty-SOAR
    application ran against it because of a GuardDuty finding.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.rds_client = self.session.client("rds")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")
        tagged_instances: List[str] = []
        errors: List[str] = []

        # The raw finding contains a LIST of RdsDbInstanceDetails
        instance_details_list = event.get("Resource", {}).get(
            "RdsDbInstanceDetails", []
        )
        if not instance_details_list:
            return {
                "status": "skipped",
                "details": "No RDS instances found in this finding.",
            }

        for instance_data in instance_details_list:
            try:
                # Construct the full ARN needed for the API call
                # Format: arn:partition:service:region:account-id:resource-type:resource-id
                instance_id = instance_data.get("DbInstanceIdentifier")
                if not instance_id:
                    continue

                region = event.get("Region")
                account_id = event.get("AccountId")
                rds_arn = f"arn:aws:rds:{region}:{account_id}:db:{instance_id}"

                logger.warning(f"ACTION: Tagging RDS instance: {instance_id}.")

                self.rds_client.add_tags_to_resource(
                    ResourceName=rds_arn,
                    Tags=cast(
                        "List[TagTypeDef]", self._tags_to_apply(event, playbook_name)
                    ),
                )
                tagged_instances.append(instance_id)

            except ClientError as e:
                details = f"Failed to add tags to RDS instance '{instance_id}': {e}"
                logger.error(details)
                errors.append(details)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Tagged: {tagged_instances}. Errors: {errors}",
            }

        return {
            "status": "success",
            "details": f"Successfully added SOAR tags to {len(tagged_instances)} RDS instance(s): {tagged_instances}.",
        }
