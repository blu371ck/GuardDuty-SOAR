import logging
import time

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class IsolateInstanceAction(BaseAction):
    """
    An action to isolate an EC2 instance by dynamically creating a new,
    deny-all security group in the instance's VPC and applying it.
    """

    # We originally were using a hard-coded sg that the end-user provided to attach to
    # instances. But it quickly became clear that we could not do that as we have no
    # way of knowing ahead of time what vpc/subnet an instance will be in that triggers
    # an alert. So, now we dynamically create one at playbook run time.
    def __init__(self, boto3_session: boto3.Session, config: AppConfig):
        super().__init__(boto3_session, config)
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        try:
            # Step 1: Extract necessary IDs from the finding
            instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
            logger.info(f"ACTION: Attempting to isolate EC2 instance: {instance_id}.")
            network_interfaces = event["Resource"]["InstanceDetails"].get(
                "NetworkInterfaces"
            )
            if not network_interfaces:
                logger.error(f"No network interfaces found for instance {instance_id}.")
                return {
                    "status": "error",
                    "details": f"No network interfaces found for instance {instance_id}.",
                }

            vpc_id = network_interfaces[0].get("VpcId")
            if not vpc_id:
                logger.error(f"No VPC ID found for instance {instance_id}.")
                return {
                    "status": "error",
                    "details": f"No VPC ID found for instance {instance_id}.",
                }

            logger.info(
                f"Beginning isolation for instance {instance_id} in VPC {vpc_id}."
            )

            # Step 2: Create a new, dedicated quarantine security group
            sg_name = f"gd-soar-quarantine-{instance_id}-{int(time.time())}"
            sg_description = (
                f"Dynamically created quarantine SG for instance {instance_id} "
                f"in response to GuardDuty finding {event['Id']}."
            )

            response = self.ec2_client.create_security_group(
                GroupName=sg_name,
                Description=sg_description,
                VpcId=vpc_id,
                # Add this TagSpecifications block to tag the resource on creation
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": "Name", "Value": sg_name},
                            {"Key": "GUARDDUTY-SOAR-ID", "Value": event["Id"]},
                        ],
                    }
                ],
            )
            new_sg_id = response["GroupId"]
            logger.info(
                f"Created and tagged new quarantine security group: {new_sg_id}"
            )

            # Step 3: Revoke the default egress rule to make it a true deny-all group
            self.ec2_client.revoke_security_group_egress(
                GroupId=new_sg_id,
                IpPermissions=[
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            )
            logger.info(
                f"Revoked default egress rule from {new_sg_id} to enforce deny-all."
            )

            # Step 4: Apply the new security group to the instance, replacing all others
            self.ec2_client.modify_instance_attribute(
                InstanceId=instance_id, Groups=[new_sg_id]
            )

            details = (
                f"Successfully isolated instance {instance_id} "
                f"by applying new security group {new_sg_id}."
            )
            logger.info(details)
            return {"status": "success", "details": details}

        except (ClientError, KeyError) as e:
            details = f"Failed to isolate instance. Error: {e}."
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
