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
    "Exfiltration:S3/AnomalousBehavior",
    "Exfiltration:S3/MaliciousIPCaller",
    "Impact:S3/AnomalousBehavior.Delete",
    "Impact:S3/AnomalousBehavior.Write",
    "Impact:S3/MaliciousIPCaller",
)
class S3DataLossPreventionPlaybook(S3CompromisedDiscoveryPlaybook):
    """
    This playbook is designed to run when there is a potential risk of data loss.
    Either from deletion, exfiltration, etc. This playbook inherits from
    S3CompromisedDiscoveryPlaybook but extends its functionality with an additional step.

    :param event: the GuardDuty event json object.
    :return: A PlaybookResult object consisting of the different steps taken and
        any details from those steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data: Dict[str, Any] = {}

        # Step 1: we run the S3CompromisedDiscoveryPlaybook and ingest its results
        result = super().run(event)
        enriched_data = result["enriched_data"] or {}
        results = result["action_results"]

        # Step 2: We scan CloudTrail history for S3 bucket-level commands issues from
        # the user principal in the GuardDuty finding.
        lookup_attributes = [
            {
                "AttributeKey": "Username",
                "AttributeValue": enriched_data["identity"]["user_name"],
            },
            {"AttributeKey": "EventSource", "AttributeValue": "s3.amazonaws.com"},
        ]

        history_result = self.get_history.execute(
            event, lookup_attributes=lookup_attributes
        )
        if history_result["status"] == "error":
            # History lookup failed
            error_details = history_result["details"]
            logger.error(f"Action 'get_history' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"GetCloudTrailHistoryAction failed: {error_details}."
            )
        results.append({**history_result, "action_name": "GetCloudTrailHistory"})
        logger.info("Successfully finished GetCloudTrailHistoryAction.")
        enriched_data["s3_cloudtrail_history"] = history_result["details"]

        return {"action_results": results, "enriched_data": enriched_data}
