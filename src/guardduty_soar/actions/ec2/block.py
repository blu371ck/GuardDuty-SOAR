import logging
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class BlockMaliciousIpAction(BaseAction):
    """
    An action to block a malicious IP address by adding 'deny' rules for it
    in the network ACL associated with the affected subnets. Both inbound/
    outbound.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ec2_client = self.session.client("ec2")

    def _get_next_available_rule_number(
        self, entries: List[Dict], is_egress: bool
    ) -> int:
        """
        Finds the next available rule number in a list of NACL entries, staying
        below 100 to avoid conflicts with default rules.
        """
        # Filter for ingress or egress rules below 100
        relevant_rules = [
            e["RuleNumber"]
            for e in entries
            if e["Egress"] == is_egress and e["RuleNumber"] < 100
        ]
        if not relevant_rules:
            return 1  # Start at 1 if no rules are in the range

        return max(relevant_rules) + 1

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        try:
            # Grab necessary information from the GaurdDuty finding:
            remote_ip = event["Service"]["Action"]["NetworkConnectionAction"][
                "RemoteIpDetails"
            ]["IpAddressV4"]
            # A deny rule will deny the traffic, regardless if there is more than one ACL due to multiple
            # subnets. So we only need to define it once, for it to be effective. Thus, we grab the first
            # subnet to simplify the process.
            subnet_id = event["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
                "SubnetId"
            ]

            logger.warning(
                f"Preparing to block malicious IP {remote_ip} for subnet {subnet_id}."
            )

            # Find a network ACL associated with the subnet
            response = self.ec2_client.describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
            )
            if not response.get("NetworkAcls"):
                return {
                    "status": "error",
                    "details": f"No network ACL found for subnet {subnet_id}.",
                }

            nacl = response["NetworkAcls"][0]
            nacl_id = nacl["NetworkAclId"]
            logger.info(f"Found Network ACL: {nacl_id}.")

            # Determine next available rules for both ingress and egress (we do both for defense in depth).
            inbound_rule_num = self._get_next_available_rule_number(
                nacl["Entries"], is_egress=False
            )
            outbound_rule_num = self._get_next_available_rule_number(
                nacl["Entries"], is_egress=True
            )

            ip_cidr = f"{remote_ip}/32"

            # Create the INBOUND deny rule
            logger.warning(
                f"ACTION: Adding INBOUND deny rule to {nacl_id} for {ip_cidr} at rule number {inbound_rule_num}."
            )
            self.ec2_client.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=inbound_rule_num,
                Protocol="-1",  # all protocols
                RuleAction="deny",
                Egress=False,
                CidrBlock=ip_cidr,
            )

            # Create the OUTBOUND deny rule
            logger.warning(
                f"ACTION: Adding OUTBOUND deny rule to {nacl_id} for {ip_cidr} at rule number {outbound_rule_num}."
            )
            self.ec2_client.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=outbound_rule_num,
                Protocol="-1",  # all protocols
                RuleAction="deny",
                Egress=True,
                CidrBlock=ip_cidr,
            )

            details = f"Successfully added inbound/outbound deny rules for {ip_cidr} to NACL {nacl_id}."
            logger.info(details)
            return {"status": "success", "details": details}

        except (ClientError, KeyError, IndexError) as e:
            details = f"Failed to block IP address. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
