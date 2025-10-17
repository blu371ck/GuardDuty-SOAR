import logging
from typing import Any, Dict, List

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import register_playbook
from guardduty_soar.playbooks.base.iam import IamBasePlaybook

logger = logging.getLogger(__name__)


@register_playbook(
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "DefenseEvasion:IAMUser/AnomalousBehavior",
    "Discovery:IAMUser/AnomalousBehavior",
    "Exfiltration:IAMUser/AnomalousBehavior",
    "Impact:IAMUser/AnomalousBehavior",
    "InitialAccess:IAMUser/AnomalousBehavior",
    "PenTest:IAMUser/KaliLinux",
    "PenTest:IAMUser/ParrotLinux",
    "PenTest:IAMUser/PentooLinux",
    "Persistence:IAMUser/AnomalousBehavior",
    "Policy:IAMUser/RootCredentialUsage",
    "Policy:IAMUser/ShortTermRootCredentialUsage",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "Recon:IAMUser/MaliciousIPCaller",
    "Recon:IAMUser/MaliciousIPCaller.Custom",
    "Recon:IAMUser/TorIPCaller",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Stealth:IAMUser/PasswordPolicyChange",
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:IAMUser/TorIPCaller",
)
class IamForensicsPlaybook(IamBasePlaybook):
    """
    Iam Forensics playbook is the only dedicated IAM playbook and covers
    most of the GuardDuty findings for IAM. We don't know any information about
    the end users environment setup. Blocking/disabling roles/users can be very
    disruptive to business operations. So, we simply try to find as much information
    on the IAM identity involved and present that information to end-users so they can
    make informed decisions faster to the GuardDuty event.

    :param event: the GuardDutyEvent JSON object.
    :return: A PlaybookResult consisting of steps taken and detailed information
        from those steps.
    """

    def run(self, event: GuardDutyEvent) -> PlaybookResult:
        enriched_data: Dict[str, Any] = {}
        results: List[ActionResult] = []

        # Step 1: We need to identify and prepare metadata about the IAM principal
        # involved in the finding.
        result = self.identify_principal.execute(event)
        if result["status"] == "error":
            # Identification failed, a.k.a failed to parse the event
            error_details = result["details"]
            logger.error(f"Action 'identify_principal' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"IdentifyPrincipalAction failed: {error_details}."
            )
        results.append({**result, "action_name": "IdentifyPrincipal"})
        logger.info("Successfully identified principal in finding.")
        identity_details = result["details"]
        enriched_data["identity"] = identity_details

        # Step 2: We tag the IAM principals involved in the findings. We can't
        # tag first, without properly parsing and identifying the principal in the finding.
        # Thus, this is step 2
        result = self.tag_principal.execute(
            event,
            playbook_name=self.__class__.__name__,
            principal_identity=identity_details,
        )
        if result["status"] == "error":
            # Tagging failed
            error_details = result["details"]
            logger.error(f"Action 'tag_principal' failed: {error_details}.")
            raise PlaybookActionFailedError(f"TagIamPrincipal failed: {error_details}.")
        results.append({**result, "action_name": "TagPrincipal"})
        logger.info("Successfully tagged associated IAM Principals.")

        # Step 3: Now that we know the principal and have tagged it. We need to
        # request more specific information that is not included in the
        # GuardDuty finding.
        result = self.get_details.execute(event, principal_details=identity_details)
        if result["status"] == "error":
            # Get details failed
            error_details = result["details"]
            logger.error(f"Action 'get_details' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"GetIamPrincipalDetails failed: {error_details}."
            )
        results.append({**result, "action_name": "GetIamPrincipalDetails"})
        logger.info("Successfully gathered IAM principal details.")
        policy_details = result["details"]
        enriched_data.update(policy_details)

        # Step 4: We gather a set amount of recent API calls using CloudTrail. The
        # number retrieved is based on user configuration.
        lookup_attributes = [
            {
                "AttributeKey": "Username",
                "AttributeValue": identity_details["user_name"],
            }
        ]

        result = self.get_history.execute(event, lookup_attributes=lookup_attributes)
        if result["status"] == "error":
            # History retrieval failed
            error_details = result["details"]
            logger.error(f"Action 'get_history' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"GetIamCloudTrailHistory failed: {error_details}."
            )
        results.append({**result, "action_name": "GetIamCloudTrailHistory"})
        logger.info("Successfully retrieved CloudTrail history.")
        enriched_data["cloudtrail_history"] = result["details"]

        # Step 5: (Optional) step, we analyze the IAM principals policies both
        # inline and managed for bad IAM practices.
        result = self.analyze_permissions.execute(
            event, principal_policies=policy_details
        )
        if result["status"] == "error":
            # Analyze step failed
            error_details = result["details"]
            logger.error(f"Action 'analyze_permissions' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"AnalyzeIamPermissions failed: {error_details}."
            )
        results.append({**result, "action_name": "AnalyzeIamPermissions"})

        if isinstance(result.get("details"), dict):
            logger.info("Successfully analyzed IAM principals permissions.")
            enriched_data["permission_analysis"] = result["details"]
        else:
            logger.info(
                f"IAM permission analysis step details: {result.get('details')}."
            )

        return {"action_results": results, "enriched_data": enriched_data}
