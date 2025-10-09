import logging
from typing import Any, Dict, List, Optional, Tuple

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

logger = logging.getLogger(__name__)


@register_playbook("Recon:EC2/PortProbeUnprotectedPort")
class EC2UnprotectedPort(EC2BasePlaybook):
    """
    This playbook class handles the finding related to an
    unprotected port being probed on an EC2 instance.
    """

    def run(
        self, event: GuardDutyEvent
    ) -> Tuple[List[ActionResult], Optional[Dict[str, Any]]]:
        logger.info(
            f"Executing EC2 Unprotected Port playbook for instance: {event['Resource']['InstanceDetails']['InstanceId']}"
        )
        results: List[ActionResult] = []
        enriched_data = None

        # Step 1: We tag the instance with special tags.
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

        # Step 2: We need to pull details from the instance to create enriched data.
        result = self.enrich_finding.execute(event, config=self.config)
        if result["status"] == "success":
            enriched_data = result["details"]
        results.append({**result, "action_name": "EnrichFinding"})
        logger.info("Successfully performed enrichment step.")

        # Step 3: We block the malicious IP performing the port probe by adding it
        # to the appropriate ACL. The ACL rules are both incoming/outgoing, "Deny" rules.
        result = self.block_ip.execute(event, config=self.config)
        if result["status"] == "error":
            # adding rules failed
            error_details = result["details"]
            logger.error(f"Action: 'block_ip' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"BlockMaliciousIPAction failed: {error_details}."
            )
        results.append({**result, "action_name": "BlockIp"})
        logger.info("Successfully blocked malicious IP address.")

        # Step 4: We remove internet access from the instances security group rules.
        # This is specifically mentioned in the finding details from AWS, "...and that
        # known scanners on the internet are actively probing it." So, this optional step
        # removes that public access. However, if your instance needs access to the
        # internet by design, you can disable this rule in configurations.
        # Resource:
        # https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeunprotectedport
        result = self.remove_rule.execute(event, config=self.config)
        if result["status"] == "error":
            # Removing rules failed
            error_details = result["details"]
            logger.error(
                f"Action: 'remove_public_access_rules' failed: {error_details}."
            )
            raise PlaybookActionFailedError(
                f"RemovePublicAccessAction failed: {error_details}."
            )
        results.append({**result, "action_name": "RemovePublicAccess"})
        logger.info("Successfully removed public access rules.")

        return results, enriched_data
