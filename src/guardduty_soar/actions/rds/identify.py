import logging
from typing import Any, Dict, List

import boto3
from pydantic import ValidationError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import RdsIdentifiedUserData, RDSInstanceDetails

logger = logging.getLogger(__name__)


class IdentifyRdsUserAction(BaseAction):
    """
    An action to identify the database user from a GuardDuty finding and
    correlate it with an IAM identity if possible.

    This action specifically checks the 'AuthMethod' in the 'DbUserDetails'.
    If the AuthMethod is 'IAM', the 'User' field is treated as an IAM identity.
    Otherwise, it is treated as a standard database-local user.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        # This action doesn't need boto3, but we accept the session
        # to maintain a consistent interface with other actions.
        super().__init__(session, config)

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        identified_users: List[Dict[str, Any]] = []
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

        for instance_data in instance_details_list:
            try:
                # Use the Pydantic model to parse the instance data
                model = RDSInstanceDetails(**instance_data, ResourceType="DBInstance")
                db_instance_id = model.db_instance_identifier

                # Check if this instance detail has the user details
                if not model.db_user_details:
                    logger.info(
                        f"No DbUserDetails for instance {db_instance_id}. Skipping."
                    )
                    continue

                db_user = model.db_user_details
                identity_type = "DatabaseUser"
                iam_identity = None

                # Check the authentication method
                if db_user.auth_method == "IAM":
                    identity_type = "IAMIdentity"
                    iam_identity = db_user.user
                    logger.warning(
                        f"Correlated DB user '{db_user.user}' to IAM identity: {iam_identity}"
                    )
                else:
                    logger.info(f"Identified standard database user: {db_user.user}")

                # Validate the output structure
                identified_data = RdsIdentifiedUserData(
                    db_user_details=db_user,
                    identity_type=identity_type,
                    iam_identity_name=iam_identity,
                )
                identified_users.append(identified_data.model_dump(exclude_none=True))

            except ValidationError as e:
                error_detail = f"Failed to validate data for instance '{instance_data.get('DbInstanceIdentifier', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)
            except Exception as e:
                error_detail = f"An unknown error occurred for instance '{instance_data.get('DbInstanceIdentifier', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Identified: {len(identified_users)} user(s).",
            }

        return {
            "status": "success",
            "details": identified_users,
        }
