import logging
from typing import List

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

logger = logging.getLogger(__name__)


@register_playbook(
    "UnauthorizedAccess:EC2/RDPBruteForce", "UnauthorizedAccess:EC2/SSHBruteForce"
)
class EC2BruteForcePlaybook(EC2BasePlaybook):
    """
    A playbook to handle brute force attempts against an EC2 instance on SSH
    or RDP. This particular finding has two scenarios. If the instance reported
    is the target (via ResourceRole), we harden the security around the instance.
    If the instance is the source, we run the compromise playbook, which is through
    the inherited method `_run_compromise_workflow`.

    :param event: the GuardDutyEvent json object.
    :return: Returns a PlaybookResult with completed steps and details.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data = None
        results: List[ActionResult] = []

        # Step 1: We find out whether the instance is the source or the target.
        # The JSON path to ResourceRole: "Service" -> "ResourceRole"
        if event["Service"]["ResourceRole"] == "SOURCE":
            # Our instance is performing the brute force. Assume compromise
            compromise_workflow_results = self._run_compromise_workflow(
                event, self.__class__.__name__
            )
            action_results = compromise_workflow_results["action_results"]
            enriched_data = compromise_workflow_results["enriched_data"]
            return {"action_results": action_results, "enriched_data": enriched_data}

        # At this point we assume our instance is being targeted by a brute-force
        # attack. So we need to harden the perimeter.
        # Step 2: Tag the instance with identifiers
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

        # Step 2: We grab the instances metadata before we modify its setup.
        result = self.enrich_finding.execute(event, config=self.config)
        if result["status"] == "success":
            enriched_data = result["details"]
        results.append({**result, "action_name": "EnrichFinding"})
        logger.info("Successfully performed enrichment step.")

        # Step 3: We block the attackers IP address in our Network ACL.
        result = self.block_ip.execute(event, config=self.config)
        if result["status"] == "error":
            # adding rules failed
            error_details = result["details"]
            logger.error(f"Action: 'block_ip' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"BlockMaliciousIpAction failed: {error_details}."
            )
        results.append({**result, "action_name": "BlockIp"})
        logger.info("Successfully blocked malicious IP address.")

        return {"action_results": results, "enriched_data": enriched_data}
