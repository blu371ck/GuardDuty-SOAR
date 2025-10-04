import logging

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import GuardDutyEvent
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

logger = logging.getLogger(__name__)


# To ensure DRY principles, we ensure that we are not recreating a playbook
# that involves the same steps as another. For instance, these GuardDuty
# finding types below, are all recommended for initiating a playbook for
# a compromised EC2 instance.
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
    "UnauthorizedAccess:EC2/MetadataDNSRebind",
    "UnauthorizedAccess:EC2/TorClient",
    "UnauthorizedAccess:EC2/TorRelay",
)
class EC2InstanceCompromisePlaybook(EC2BasePlaybook):
    """
    This playbook class handles multiple finding types related to a
    compromised EC2 instance.
    """

    def run(self, event: GuardDutyEvent):
        logger.info(
            f"Executing EC2 Instance Compromise playbook for instance: {event['Resource']['InstanceDetails']['InstanceId']}"
        )

        # Step 1: This playbook always assumes compromise, so it directly calls the
        # inherited workflow.
        self._run_compromise_workflow(event, self.__class__.__name__)

        # Step 5: Enrich the GuardDuty finding event with metadata about the
        # compromised EC2 instance. This data is then passed through to the end-user
        # via the notification methods coming up.
        enrichment_result = self.enrich_finding.execute(event, config=self.config)
        if enrichment_result["status"] == "error":
            # Enrichment failed
            error_details = enrichment_result["details"]
            logger.error(f"Action: 'enrich_finding' failed: {error_details}.")
            # Passing basic enriched object to allow notification to proceed.
            enriched_finding = {"guardduty_finding": event, "instance_metadata": {}}
        else:
            enriched_finding = enrichment_result["details"]
            logger.info("Successfully performed enrichment step.")

        snapshot_result = self.create_snapshots.execute(event, config=self.config)
        if snapshot_result["status"] == "error":
            # Snapshotting failed
            error_details = snapshot_result["details"]
            logger.error(f"Action: 'create_snapshot' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"CreateSnapshotAction failed: {error_details}."
            )

        logger.info(f"Successfully ran playbook on instance:")
