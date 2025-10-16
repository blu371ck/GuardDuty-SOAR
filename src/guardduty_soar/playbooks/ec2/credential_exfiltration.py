import logging
from typing import List

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.ec2 import EC2BasePlaybook

logger = logging.getLogger(__name__)


@register_playbook("UnauthorizedAccess:EC2/MetadataDNSRebind")
class EC2CredentialExfiltrationPlaybook(EC2BasePlaybook):
    """
    A Playbook to handle the GuardDuty finding of `UnauthorizedAccess:EC2/MetadataDNSRebind`.
    Where a potential DNS rebinding attack could be occurring.

    :param event: the GuardDutyEvent json object.
    :return: A PlaybookResult object consisting of steps taken and details from
        those steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data = None
        results: List[ActionResult] = []

        # Step 1: Tag the instance with metadata that a playbook ran against it.
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

        # Step 2: We grab the instance metadata before we modify it.
        result = self.enrich_finding.execute(event, config=self.config)
        if result["status"] == "success":
            enriched_data = result["details"]
        results.append({**result, "action_name": "EnrichFinding"})
        logger.info("Successfully performed enrichment step.")

        # Step 3: We isolate the instance to stop any malicious activity in
        # progress.
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

        # Step 4: We quarantine the instance profile by adding a deny policy
        # if there is an instance profile
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

        # Step 5: We take a snapshot of any EBS volumes attached.
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

        # return results
        return {"action_results": results, "enriched_data": enriched_data}
