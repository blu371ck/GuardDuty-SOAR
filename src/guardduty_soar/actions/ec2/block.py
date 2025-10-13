import logging

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

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        ips_to_block = []
        try:
            action_type = event["Service"]["Action"]["ActionType"]

            # Step 1: Extract IP(s) to block based on the Action Type
            if action_type == "NETWORK_CONNECTION":
                remote_ip = event["Service"]["Action"]["NetworkConnectionAction"]["RemoteIpDetails"]["IpAddressV4"]
                if remote_ip:
                    ips_to_block.append(remote_ip)
                logger.info(f"Identified single IP to block: {remote_ip}")
            
            elif action_type == "PORT_PROBE":
                port_probe_details = event["Service"]["Action"]["PortProbeAction"].get("PortProbeDetails", [])
                for probe in port_probe_details:
                    remote_ip = probe.get("RemoteIpDetails", {}).get("IpAddressV4")
                    if remote_ip and remote_ip not in ips_to_block:
                        ips_to_block.append(remote_ip)
                logger.info(f"Identified {len(ips_to_block)} unique IP(s) from PortProbe details.")
            
            else:
                details = f"Action type '{action_type}' is not supported for IP blocking."
                logger.warning(details)
                return {"status": "skipped", "details": details}

            if not ips_to_block:
                return {"status": "success", "details": "No IP addresses were identified to block."}

            # Step 2: Get the Network ACL for the instance's subnet
            subnet_id = event["Resource"]["InstanceDetails"]["NetworkInterfaces"][0]["SubnetId"]
            response = self.ec2_client.describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
            )
            if not response.get("NetworkAcls"):
                return {"status": "error", "details": f"No network ACL found for subnet {subnet_id}."}

            nacl = response["NetworkAcls"][0]
            nacl_id = nacl["NetworkAclId"]
            logger.info(f"Found Network ACL: {nacl_id} for subnet {subnet_id}.")

            # Step 3: Determine the next available rule numbers
            existing_rules = [e["RuleNumber"] for e in nacl["Entries"] if e["RuleNumber"] < 100]
            last_rule_num = max(existing_rules) if existing_rules else 0

            # Step 4: Loop through all identified IPs and create deny rules for each
            for ip in ips_to_block:
                inbound_rule_num = last_rule_num + 1
                outbound_rule_num = last_rule_num + 2
                ip_cidr = f"{ip}/32"

                logger.warning(f"ACTION: Adding INBOUND deny rule to {nacl_id} for {ip_cidr} at rule number {inbound_rule_num}.")
                self.ec2_client.create_network_acl_entry(
                    NetworkAclId=nacl_id, RuleNumber=inbound_rule_num, Protocol="-1",
                    RuleAction="deny", Egress=False, CidrBlock=ip_cidr,
                )

                logger.warning(f"ACTION: Adding OUTBOUND deny rule to {nacl_id} for {ip_cidr} at rule number {outbound_rule_num}.")
                self.ec2_client.create_network_acl_entry(
                    NetworkAclId=nacl_id, RuleNumber=outbound_rule_num, Protocol="-1",
                    RuleAction="deny", Egress=True, CidrBlock=ip_cidr,
                )
                
                # Increment the rule number for the next IP in the loop
                last_rule_num += 2

            details = f"Successfully added inbound/outbound deny rules for {len(ips_to_block)} IP(s) to NACL {nacl_id}."
            logger.info(details)
            return {"status": "success", "details": details}

        except (ClientError, KeyError, IndexError) as e:
            details = f"Failed to block IP address. Error: {e}."
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
