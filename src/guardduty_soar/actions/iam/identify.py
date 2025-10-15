import logging

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class IdentifyIamPrincipalAction(BaseAction):
    """
    An action to parse the GuardDuty finding and identify the core
    details of the IAM principal (user or role) involved in the
    event.
    """

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        logger.info("Attempting to identify IAM principal from GuardDuty finding.")

        try:
            # The key details are in the Resource.AccessKeyDetails section
            principal_details = event["Resource"]["AccessKeyDetails"]
            logger.warning(
                f"ACTION: Attempting to identify principal: {principal_details}."
            )
            user_type = principal_details.get("UserType")
            user_name = principal_details.get("UserName")
            account_id = event.get("AccountId")
            principal_arn = ""

            # Construct a probably ARN based on the UserType
            if user_type == "IAMUser":
                principal_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            elif user_type == "AssumedRole":
                # For assumed roles, UserName is often 'RoleName/SessionName'
                role_name = user_name.split("/")[0] if user_name else ""
                principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            elif user_type == "Root":
                principal_arn = f"arn:aws:iam::{account_id}:root"

            # Packaging the finding into a clean directory
            result_details = {
                "access_key_id": principal_details.get("AccessKeyId"),
                "principal_id": principal_details.get("PrincipalId"),
                "user_type": user_type,
                "user_name": user_name,
                "principal_arn": principal_arn,
            }

            logger.info(
                f"Successfully identified principal: {principal_arn or user_name}."
            )
            return {"status": "success", "details": result_details}

        except KeyError as e:
            details = f"Finding is missing expected key path for principal identification: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
