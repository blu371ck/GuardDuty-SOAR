import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class ModifyRdsPublicAccessAction(BaseAction):
    """
    An action to revoke public access from an RDS DB instance by setting its
    'PubliclyAccessible' flag to False. This is a destructive action that
    can cause outages and is controlled by a configuration flag.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.rds_client = self.session.client("rds")
        self.allow_revoke = getattr(config, "allow_revoke_public_access_rds", False)

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Executes the logic to modify the RDS instance's public access setting.
        """
        if not self.allow_revoke:
            return {
                "status": "skipped",
                "details": "Configuration 'allow_revoke_public_access_rds' is False.",
            }

        modified_instances: List[str] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "DBInstance":
            return {
                "status": "skipped",
                "details": "Resource type is not DBInstance.",
            }

        instance_details_list = resource_data.get("RdsDbInstanceDetails", [])
        if not instance_details_list:
            return {
                "status": "skipped",
                "details": "No RDS instances listed in this finding.",
            }

        for instance in instance_details_list:
            db_instance_id = instance.get("DbInstanceIdentifier")
            if not db_instance_id:
                continue

            logger.warning(
                f"ACTION: Attempting to revoke public access for RDS instance: {db_instance_id}"
            )
            try:
                self.rds_client.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True,  # Critical for timely security response
                )
                logger.info(
                    f"Successfully submitted modification for {db_instance_id} to revoke public access."
                )
                modified_instances.append(db_instance_id)

            except ClientError as e:
                error_detail = f"Failed to modify {db_instance_id}: {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Modified: {len(modified_instances)} instance(s).",
            }

        return {
            "status": "success",
            "details": f"Successfully submitted modification request for {len(modified_instances)} instance(s).",
        }
