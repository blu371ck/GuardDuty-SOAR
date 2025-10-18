import logging
from typing import Any, Dict, List

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.s3 import S3BasePlaybook

logger = logging.getLogger(__name__)


@register_playbook(
    "Discovery:S3/MaliciousIPCaller",
    "Discovery:S3/MaliciousIPCaller.Custom",
    "Discovery:S3/AnomalousBehavior",
    "Discovery:S3/TorIPCaller",
    "PenTest:S3/KaliLinux",
    "PenTest:S3/ParrotLinux",
    "PenTest:S3/PentooLinux",
    "Stealth:S3/ServerAccessLoggingDisabled",
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:S3/TorIPCaller",
)
class S3CompromisedDiscoveryPlaybook(S3BasePlaybook):
    """
    This playbook is designed to run when potential discovery based attacks are
    taking place. S3 is more complicated than other services, and generally requires
    detailed information not only about the S3 object, but also the IAM principals
    making the calls against it.

    :param event: the GuardDutyEvent JSON object.
    :return: A PlaybookResult object consisting of the different steps taken and
        any details from those steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data: Dict[str, Any] = {}
        results: List[ActionResult] = []

        # Step 1: We need to tag the S3 bucket in question.
        result = self.tag_s3_bucket.execute(
            event, playbook_name=self.__class__.__name__
        )
        if result["status"] == "error":
            # tagging failed
            error_details = result["details"]
            logger.error(f"Action 'tag_s3_buckets' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"TagS3BucketAction failed: {error_details}."
            )
        results.append({**result, "action_name": "TagS3Bucket"})
        logger.info("Successfully tagged bucket(s).")

        # Step 2: We identify the IAM principal involved.
        result = self.identify_principal.execute(event)
        if result["status"] == "error":
            # Identification failed
            error_details = result["details"]
            logger.error(f"Action 'identify_principal' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"IdentifyPrincipalAction failed: {error_details}."
            )
        results.append({**result, "action_name": "IdentifyIamPrincipal"})
        logger.info("Successfully identified principal in finding.")
        identity_details = result["details"]
        enriched_data["identity"] = identity_details

        # Step 3: We tag the IAM principal involved.
        result = self.tag_principal.execute(
            event,
            playbook_name=self.__class__.__name__,
            principal_identity=identity_details,
        )
        if result["status"] == "error":
            # tagging of principal failed
            error_details = result["details"]
            logger.error(f"Action 'tag_principal' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"TagIamPrincipalAction failed: {error_details}."
            )
        results.append({**result, "action_name": "TagIamPrincipal"})
        logger.info("Successfully tagged associated IAM principal.")

        # Step 4: We gather enriched data about the bucket and its policies.
        result = self.get_s3_enrichment.execute(event)
        if result["status"] == "error":
            # Enrichment failed
            error_details = result["details"]
            logger.error(f"Action 'enrich_s3_data' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"EnrichS3BucketAction failed: {error_details}."
            )
        results.append({**result, "action_name": "EnrichS3Bucket"})
        enriched_data["s3_bucket_details"] = result["details"]
        logger.info("Successfully enriched S3 finding.")

        # Step 5: (Optional) step, if enabled we quarantine the IAM Principal from
        # the finding.
        result = self.quarantine_principal.execute(event, identity=identity_details)
        if result["status"] == "error":
            # Quarantine failed
            error_details = result["details"]
            logger.error(f"Action 'quarantine_iam_principal' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"QuarantineIamPrincipalAction failed: {error_details}."
            )
        results.append({**result, "action_name": "QuarantineIamPrincipal"})

        if result["status"] != "error":
            logger.info(
                f"Quarantine IAM Principal step finished with status '{result['status']}': {result['details']}."
            )

        return {"action_results": results, "enriched_data": enriched_data}
