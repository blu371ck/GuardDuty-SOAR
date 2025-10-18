import logging
from typing import List

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

logger = logging.getLogger(__name__)


# To ensure DRY principles, we ensure that we are not recreating a playbook
# that involves the same steps as another. For instance, these GuardDuty
# finding types below, are all recommended for initiating a playbook for
# a compromised EC2 instance. There is also two IAM findings here, that
# pertain to a compromised EC2 instance as their severity is high, we
# utilize this playbook for full forensics.
@register_playbook(
    "Backdoor:EC2/C&CActivity.B",
    "Backdoor:EC2/C&CActivity.B!DNS",
    "Backdoor:EC2/DenialOfService.Dns",
    "Backdoor:EC2/DenialOfService.Tcp",
    "Backdoor:EC2/DenialOfService.Udp",
    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
    "Backdoor:EC2/DenialOfService.UnusualProtocol",
    "Backdoor:EC2/Spambot",
    "Behavior:EC2/NetworkPortUnusual",
    "Behavior:EC2/TrafficVolumeUnusual",
    "CryptoCurrency:EC2/BitcoinTool.B",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "DefenseEvasion:EC2/UnusualDNSResolver",
    "DefenseEvasion:EC2/UnusualDoHActivity",
    "DefenseEvasion:EC2/UnusualDoTActivity",
    "Impact:EC2/AbusedDomainRequest.Reputation",
    "Impact:EC2/BitcoinDomainRequest.Reputation",
    "Impact:EC2/MaliciousDomainRequest.Reputation",
    "Impact:EC2/MaliciousDomainRequest.Custom",
    "Impact:EC2/PortSweep",
    "Impact:EC2/SuspiciousDomainRequest.Reputation",
    "Impact:EC2/WinRMBruteForce",
    "Recon:EC2/Portscan",
    "Trojan:EC2/BlackholeTraffic",
    "Trojan:EC2/BlackholeTraffic!DNS",
    "Trojan:EC2/DGADomainRequest.B",
    "Trojan:EC2/DGADomainRequest.C!DNS",
    "Trojan:EC2/DNSDataExfiltration",
    "Trojan:EC2/DriveBySourceTraffic!DNS",
    "Trojan:EC2/DropPoint",
    "Trojan:EC2/DropPoint!DNS",
    "Trojan:EC2/PhishingDomainRequest!DNS",
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:EC2/TorClient",
    "UnauthorizedAccess:EC2/TorRelay",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
)
class EC2InstanceCompromisePlaybook(EC2BasePlaybook):
    """
    This playbook class handles multiple finding types related to a compromised EC2
    instance. Since the `_run_compromise_workflow` method is inherited, it's used by
    this class during its run method.

    :param event: the GuardDutyEvent JSON object.
    :return: A PlaybookResult object consisting of steps taken and details from those
        steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        logger.info(
            f"Executing EC2 Instance Compromise playbook for instance: {event['Resource']['InstanceDetails']['InstanceId']}"
        )

        results: List[ActionResult] = []
        enriched_data = None

        # Step 1: Tag the instance with special tags.
        result = self.tag_instance.execute(event, playbook_name=self.__class__.__name__)
        if result["status"] == "error":
            # tagging failed
            error_details = result["details"]
            logger.error(f"Action 'tag_instance' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"TagInstanceAction failed: {error_details}."
            )
        results.append({**result, "action_name": "TagInstance"})
        logger.info("Successfully tagged instance.")

        # Step 2: Isolate the instance with a quarantined SG. Ideally
        # the security group should not have any inbound/outbound rules, and
        # all other security groups previously used by the instance are removed.
        result = self.isolate_instance.execute(event, config=self.config)
        if result["status"] == "error":
            # Isolation failed
            error_details = result["details"]
            logger.error(f"Action 'isolate_instance' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"IsolateInstanceAction failed: {error_details}."
            )
        results.append({**result, "action_name": "IsolateInstance"})
        logger.info("Successfully isolated instance.")

        # Step 3: Attach a deny all policy to the IAM instance profile associated
        # with the instance. We check if there is an instance profile, if there
        # isn't we return success and move on.
        result = self.quarantine_profile.execute(event, config=self.config)
        if result["status"] == "error":
            # Quarantine failed
            error_details = result["details"]
            logger.error(f"Action 'quarantine_profile' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"QuarantineInstanceProfileAction failed: {error_details}."
            )
        results.append({**result, "action_name": "QuarantineInstance"})
        logger.info("Successfully quarantined instance profile.")

        # Step 4: Create snapshots of all attached EBS volumes. Programmatically
        # checks for number and if any exists and iterates over them all. As we
        # do not know if/where any malicious activity could be nested in the
        # volumes. Appropriate tags are added as part of the call to
        # create_snapshot boto3 command.
        result = self.create_snapshots.execute(event, config=self.config)
        if result["status"] == "error":
            # Snapshotting failed
            error_details = result["details"]
            logger.error(f"Action: 'create_snapshot' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"CreateSnapshotAction failed: {error_details}."
            )
        results.append({**result, "action_name": "CreateSnapshot"})
        logger.info("Successfully took snapshot(s) of instances volumes.")

        # Step 5: Enrich the GuardDuty finding event with metadata about the
        # compromised EC2 instance. This data is then passed through to the end-user
        # via the notification methods coming up.
        result = self.enrich_finding.execute(event, config=self.config)
        if result["status"] == "success":
            enriched_data = result["details"]
        results.append({**result, "action_name": "EnrichFinding"})
        logger.info("Successfully performed enrichment step.")

        # Step 6: Terminate the instance, if user has selected for destructive actions.
        result = self.terminate_instance.execute(event, config=self.config)
        if result["status"] == "error":
            # Termination failed
            error_details = result["details"]
            logger.error(f"Action: 'terminate_instance' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"TerminateInstanceAction failed: {error_details}."
            )
        results.append({**result, "action_name": "TerminateInstance"})
        logger.info("Successfully terminated")

        logger.info(f"Playbook execution finished for {self.__class__.__name__}.")

        return {"action_results": results, "enriched_data": enriched_data}
