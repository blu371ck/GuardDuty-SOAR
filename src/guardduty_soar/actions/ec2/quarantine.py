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
    'deny-all' policy to it. This action fetches live instance data to ensure accuracy.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        # Initialize instance_profile_arn to prevent unbound variable error.
        instance_profile_arn = ""

        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not response.get("Reservations") or not response["Reservations"][0].get("Instances"):
                details = f"Instance {instance_id} not found. Skipping role quarantine."
                logger.warning(details)
                return {"status": "success", "details": details}

            instance_metadata = response["Reservations"][0]["Instances"][0]
            iam_profile = instance_metadata.get("IamInstanceProfile")

            if not iam_profile or not iam_profile.get("Arn"):
                details = f"Instance {instance_id} has no IAM instance profile. Skipping role quarantine."
                logger.info(details)
                return {"status": "success", "details": details}
            
            instance_profile_arn = iam_profile["Arn"]
            role_name = instance_profile_arn.split("/")[-1]
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
            error_code = e.response.get("Error", {}).get("Code")
            # Check if error_code exists before deeper checks.
            if error_code and "NotFound" in error_code:
                 details = f"Instance {instance_id} not found. Skipping role quarantine."
                 logger.warning(details)
                 return {"status": "success", "details": details}
            
            details = f"Failed to attach deny policy to role. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except IndexError:
            details = f"Could not parse role name from instance profile ARN: {instance_profile_arn}"
            logger.error(details)
            return {"status": "error", "details": details}