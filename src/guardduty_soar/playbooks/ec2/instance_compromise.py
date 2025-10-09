import logging

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
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
)
class EC2InstanceCompromisePlaybook(EC2BasePlaybook):
    """
    This playbook class handles multiple finding types related to a
    compromised EC2 instance.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        logger.info(
            f"Executing EC2 Instance Compromise playbook for instance: {event['Resource']['InstanceDetails']['InstanceId']}"
        )

        # Step 1: This playbook always assumes compromise, so it directly calls the
        # inherited workflow. This is specifically because downstream there are event findings
        # where the resource could be the "target" or the "actor". Depending on the situation
        # downstream we want to either run one of two playbooks. Moving that base instance
        # compromise workflow to the base class allows all classes to inherit it and use
        # conditional logic to decide based on "actor" or "target" if it should run it or
        # something else.
        compromise_workflow_results = self._run_compromise_workflow(
            event, self.__class__.__name__
        )

        action_results = compromise_workflow_results["action_results"]
        enriched_data = compromise_workflow_results["enriched_data"]
        return {"action_results": action_results, "enriched_data": enriched_data}
