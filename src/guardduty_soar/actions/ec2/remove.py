from __future__ import annotations

import logging
from typing import Any, Dict, List, cast, TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

if TYPE_CHECKING:
    from mypy_boto3_ec2.type_defs import IpPermissionTypeDef

logger = logging.getLogger(__name__)


class RemovePublicAccessAction(BaseAction):
    """
    An action to review the security groups attached to an instance and remove any
    inbound rules that allow unrestricted public access. This action is optional
    and can be controlled by the applications configurations `allow_revoke_public_access`.

    :param session: a Boto3 Session object to make clients with.
    :param config: the Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        # If disabled, carry on.
        if not getattr(self.config, "allow_remove_public_access", True):
            details = (
                "Action 'allow_remove_public_access' is disabled in config. Skipping."
            )
            logger.warning(details)
            return {"status": "skipped", "details": details}

        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        logger.info(
            f"ACTION: Attempting to remove public access to instance: {instance_id}."
        )
        revoked_rules_summary = []

        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            if not response.get("Reservations") or not response["Reservations"][0].get(
                "Instances"
            ):
                logger.warning(
                    f"No instances {instance_id} found. Potentially already terminated."
                )
                return {
                    "status": "success",
                    "details": f"Instance {instance_id} not found.",
                }

            instance_info = response["Reservations"][0]["Instances"][0]
            security_groups = instance_info.get("SecurityGroups", [])

            if not security_groups:
                logger.warning(f"No security groups found for instance {instance_id}.")
                return {
                    "status": "success",
                    "details": f"No security groups found on instance {instance_id}.",
                }

            # Iterate through all connected SGs.
            for sg in security_groups:
                sg_id = sg["GroupId"]
                logger.info(
                    f"Reviewing security group {sg_id} for public access rules."
                )

                sg_details = self.ec2_client.describe_security_groups(GroupIds=[sg_id])[
                    "SecurityGroups"
                ][0]

                rules_to_revoke_for_sg: List[Dict[str, Any]] = []

                # Iterate through each rule.
                for rule in sg_details.get("IpPermissions", []):
                    # Find all public IPv4 and IPv6 ranges within this single rule
                    public_ipv4_ranges = [
                        r
                        for r in rule.get("IpRanges", [])
                        if r.get("CidrIp") == "0.0.0.0/0"
                    ]
                    public_ipv6_ranges = [
                        r
                        for r in rule.get("Ipv6Ranges", [])
                        if r.get("CidrIpv6") == "::/0"
                    ]

                    # If this rule contains any public ranges, construct a new, clean
                    # rule object containing ONLY those public ranges for revocation.
                    if public_ipv4_ranges or public_ipv6_ranges:
                        revocation_rule: Dict[str, Any] = {
                            "IpProtocol": rule["IpProtocol"],
                            "FromPort": rule.get("FromPort"),
                            "ToPort": rule.get("ToPort"),
                        }
                        if public_ipv4_ranges:
                            revocation_rule["IpRanges"] = public_ipv4_ranges
                        if public_ipv6_ranges:
                            revocation_rule["Ipv6Ranges"] = public_ipv6_ranges

                        rules_to_revoke_for_sg.append(revocation_rule)

                if rules_to_revoke_for_sg:
                    logger.warning(
                        f"ACTION: Found {len(rules_to_revoke_for_sg)} public rule(s) in {sg_id}. Preparing to revoke."
                    )
                    self.ec2_client.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=cast(
                            "List[IpPermissionTypeDef]", rules_to_revoke_for_sg
                        ),
                    )
                    revoked_rules_summary.append(
                        f"Removed {len(rules_to_revoke_for_sg)} public rule(s) from {sg_id}."
                    )
                    logger.info(
                        f"Successfully revoked {len(rules_to_revoke_for_sg)} public rule(s) from {sg_id}."
                    )

            if not revoked_rules_summary:
                details = "No public access rules found to remove."
                logger.info(details)
                return {"status": "success", "details": details}

            final_details = " ".join(revoked_rules_summary)
            return {"status": "success", "details": final_details}

        except ClientError as e:
            details = (
                f"Failed to remove public access for instance {instance_id}. Error: {e}"
            )
            logger.error(details)
            return {"status": "error", "details": details}
