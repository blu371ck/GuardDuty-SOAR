import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class QuarantineIamPrincipalAction(BaseAction):
    """
    An action to quarantine an IAM principal. The process of quarantining
    is simply attaching the aws managed `AWSDenyAll` policy or the configured
    `iam_deny_all_policy_arn` from the configuration. This alters
    their permissions to explicitly deny all actions/resources. Since deny
    actions override allow actions, the user essentially is quarantined until
    the activities can be further reviewed. This action is optional and is
    controlled by a configuration flag `allow_iam_quarantine`.

    :param session: a Boto3 Session object to create clients with.
    :param config: the Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        identity_details: Dict[str, Any] = kwargs.get("identity", {})

        if not self.config.allow_iam_quarantine:
            return {
                "status": "skipped",
                "details": "Quarantine IAM principal(s) is disabled in the configuration.",
            }

        if not identity_details or not isinstance(identity_details, dict):
            logger.error(
                "Identity details provided to QuarantineIamPrincipalAction are invalid."
            )
            return {
                "status": "error",
                "details": "Identity details provided are empty or invalid.",
            }

        logger.warning(
            f"ACTION: Attempting to quarantine IAM principal: {identity_details['principal_arn']}."
        )
        try:
            user_type = identity_details.get("user_type", "Unknown")
            user_name = identity_details.get("user_name")

            if not user_name:
                return {
                    "status": "error",
                    "details": "No username provided to QuarantineIamPrincipalAction",
                }

            if user_type == "Root":
                logger.warning("Cannot quarantine a root user, skipping action.")
                return {
                    "status": "skipped",
                    "details": "Skipping action, cannot quarantine a root user.",
                }
            elif user_type == "IAMUser":
                self.iam_client.attach_user_policy(
                    UserName=user_name, PolicyArn=self.config.iam_deny_all_policy_arn
                )
                logger.info(
                    f"Successfully attached quarantine policy to user: {user_name}."
                )
            else:
                self.iam_client.attach_role_policy(
                    RoleName=user_name, PolicyArn=self.config.iam_deny_all_policy_arn
                )
                logger.info(
                    f"Successfully attached quarantine policy to role: {user_name}."
                )

            return {
                "status": "success",
                "details": f"Successfully attached quarantine policy to IAM principal: {identity_details['principal_arn']}.",
            }

        except ClientError as e:
            details = f"An error occurred attaching quarantine policy: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
