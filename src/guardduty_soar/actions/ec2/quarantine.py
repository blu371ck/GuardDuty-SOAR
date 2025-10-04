import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class QuarantineInstanceProfileAction(BaseAction):
    """
    An action to quarantine an EC2 instance's IAM role by attaching a
    'deny-all' policy to it. This effectively revokes its IAM credentials,
    as a deny all policy trumps any underlying permissions.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        # We need to check if there is an IAM instance profile first,
        # not all EC2 instances will have an IAM instance profile attached.
        instance_profile_details = event["Resource"]["InstanceDetails"].get(
            "IamInstanceProfile"
        )
        if not instance_profile_details or "Arn" not in instance_profile_details:
            details = (
                "No IAM Instance Profile found on instance. Skipping role quarantine."
            )
            logger.warning(details)
            return {"status": "success", "details": details}

        try:
            # We need to extract the roles name, which is the last part of
            # the full ARN.
            instance_profile_arn = instance_profile_details["Arn"]
            role_name = instance_profile_arn.split("/")[-1]

            # Grab the deny policy from the configurations.
            deny_policy_arn = self.config.iam_deny_all_policy_arn

            logger.warning(
                f"ACTION: Attaching deny-all policy ({deny_policy_arn}) to IAM role ({role_name})."
            )

            self.iam_client.attach_role_policy(
                RoleName=role_name, PolicyArn=deny_policy_arn
            )

            details = f"Successfully attached deny-all policy to role {role_name}."
            logger.info(details)
            return {"status": "success", "details": details}

        except ClientError as e:
            details = f"Failed to attach deny policy to role. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except IndexError as e:
            # In case ARN parsing fails for any reason
            details = f"Could not parse role name from instance profile."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            # Generic catch all.
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
