import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class TagIamPrincipalAction(BaseAction):
    """
    An action to tag an IAM principal (user or role). This indicates
    that a security event has occurred and provides visibility that
    a playbook has taken action against it.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        principal_identity = kwargs.get("principal_identity")
        if not principal_identity:
            return {
                "status": "error",
                "details": "Required 'principal_identity' was not provided.",
            }

        logger.warning(f"ACTION: Tagging IAM principal: {principal_identity}.")

        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")
        user_type = principal_identity.get("user_type")
        user_name = principal_identity.get("user_name")

        # The root user cannot be tagged, so we skip this action.
        if user_type == "Root":
            details = "Skipping tag action: The AWS Account Root user cannot be tagged."
            logger.warning(details)
            return {"status": "skipped", "details": details}

        try:

            if user_type == "IAMUser":
                logger.info(f"Tagging IAM user: {user_name}.")
                self.iam_client.tag_user(
                    UserName=user_name, Tags=self._tags_to_apply(event, playbook_name)
                )
                principal_display_name = user_name
            elif user_type in ["AssumedRole", "Role"]:
                # For AssumeRole, user_name is often 'RoleName/SessionName'.
                # We need to extract just the RoleName.
                role_name = user_name.split("/")[0]
                logger.info(f"Tagging IAM role: {role_name}.")
                self.iam_client.tag_role(
                    RoleName=role_name, Tags=self._tags_to_apply(event, playbook_name)
                )
                principal_display_name = role_name
            else:
                details = f"Cannot tag unknown principal type: {user_type}."
                logger.error(details)
                return {"status": "error", "details": details}

            details = (
                f"Successfully added SOAR tags to principal: {principal_display_name}."
            )
            logger.info(details)
            return {"status": "success", "details": details}

        except ClientError as e:
            details = f"Failed to add tags to principal: {user_name}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except KeyError as e:
            # In case of malformed events.
            details = f"Failed to create tags because the event is missing a required key: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
