import logging
from typing import Any, Dict

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.s3.compromised_discovery import (
    S3CompromisedDiscoveryPlaybook,
)

logger = logging.getLogger(__name__)


@register_playbook(
    "Impact:S3/AnomalousBehavior.Permission",
    "Policy:S3/AccountBlockPublicAccessDisabled",
    "Policy:S3/BucketAnonymousAccessGranted",
    "Policy:S3/BucketBlockPublicAccessDisabled",
    "Policy:S3/BucketPublicAccessGranted",
)
class S3BucketExposurePlaybook(S3CompromisedDiscoveryPlaybook):
    """
    This playbook is designed to run when there is potential for an S3 bucket
    to be publicly exposed, because of actions from an IAM principal. This
    playbook inherits from the S3CompromiseDiscoveryPlaybook, which runs its
    workflow first, then runs the additional optional step of `S3BlockPublicAccessAction`.
    The action `S3BlockPublicAccessAction` is controlled by the configuration
    flag `allow_s3_public_block`.

    :param event: the GuardDuty event JSON object.
    :return: A PlaybookResult object consisting of the different steps taken and
        any details collected from those steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data: Dict[str, Any] = {}

        # Step 1: We run the S3CompromisedDiscoveryPlaybook and ingest its results
        result = super().run(event)
        enriched_data = result["enriched_data"] or {}
        results = result["action_results"]

        # Step 2: We attach a block public access policy to the bucket.
        policy_result = self.attach_block.execute(event)
        if policy_result["status"] == "error":
            # Attaching policy failed
            error_details = policy_result["details"]
            logger.error(f"Action 'attach_block_policy' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"S3BlockPublicAccessAction failed: {error_details}."
            )
        results.append({**policy_result, "action_name": "S3BlockPublicAccess"})

        if policy_result["status"] != "error":
            logger.info(
                f"S3 Block Public Access step finished with status '{policy_result['status']}': {policy_result['details']}"
            )

        return {"action_results": results, "enriched_data": enriched_data}
