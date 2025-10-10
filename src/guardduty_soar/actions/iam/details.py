import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class GetIamPrincipalDetailsAction(BaseAction):
    """
    An action to get detailed information about an IAM principal
    (user or role) including creation date, tags, and attached/inline policies.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")

    def _get_user_details(self, user_name: str) -> Dict[str, Any]:
        """Helper method to gather details for an IAM user."""
        user_info = self.iam_client.get_user(UserName=user_name)["User"]
        attached_policies = self.iam_client.list_attached_user_policies(
            UserName=user_name
        ).get("AttachedPolicies", [])
        inline_policy_names = self.iam_client.list_user_policies(
            UserName=user_name
        ).get("PolicyNames", [])

        inline_policies = {}
        for policy_name in inline_policy_names:
            inline_policies[policy_name] = self.iam_client.get_user_policy(
                UserName=user_name, PolicyName=policy_name
            )["PolicyDocument"]

        return {
            "details": user_info,
            "attached_policies": attached_policies,
            "inline_policies": inline_policies,
        }

    def _get_role_details(self, role_name: str) -> Dict[str, Any]:
        """Helper method to gather details for an IAM role."""
        role_info = self.iam_client.get_role(RoleName=role_name)["Role"]
        attached_policies = self.iam_client.list_attached_role_policies(
            RoleName=role_name
        ).get("AttachedPolicies", [])
        inline_policy_names = self.iam_client.list_role_policies(
            RoleName=role_name
        ).get("PolicyNames", [])

        inline_policies = {}
        for policy_name in inline_policy_names:
            inline_policies[policy_name] = self.iam_client.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )["PolicyDocument"]

        return {
            "details": role_info,
            "attached_policies": attached_policies,
            "inline_policies": inline_policies,
        }

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        principal_details = kwargs.get("principal_details")
        if not principal_details:
            return {
                "status": "error",
                "details": "Required 'principal_details' were not provided.",
            }

        user_type = principal_details.get("user_type")
        user_name = principal_details.get("user_name")
        logger.info(f"Getting IAM details for {user_type}: {user_name}.")

        try:
            if user_type == "IAMUser":
                result_details = self._get_user_details(user_name)
            elif user_type in ["AssumedRole", "Role"]:
                role_name = user_name.split("/")[0]
                result_details = self._get_role_details(role_name)
            elif user_type == "Root":
                result_details = {"details": "Principal is the AWS Account Root user."}
            else:
                return {"status": "error", "details": f"Unknown UserType: {user_type}."}

            return {"status": "success", "details": result_details}

        except ClientError as e:
            details = f"Failed to get details for {user_name}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
