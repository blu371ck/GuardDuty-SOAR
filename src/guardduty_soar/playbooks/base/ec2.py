import logging
from typing import List

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction
from guardduty_soar.actions.ec2.enrich import EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.quarantine import QuarantineInstanceProfileAction
from guardduty_soar.actions.ec2.remove import RemovePublicAccessAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction
from guardduty_soar.config import AppConfig
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import ActionResult, GuardDutyEvent, PlaybookResult
from guardduty_soar.playbook_registry import BasePlaybook

logger = logging.getLogger(__name__)


class EC2BasePlaybook(BasePlaybook):
    """
    An intermediate base class for all playbooks that respond to EC2 findings.

    Inherits the boto3 Session() from BasePlaybook and initializes all relevant
    EC2 action classes.

    :param config: the Applications configurations.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config)
        # For each child of the BasePlaybook class we will register all actions
        # applicable to all playbooks regarding that type. For instance, this is
        # going to store all actions applicable to playbooks that are applicable to
        # EC2 reports/findings.
        self.tag_instance = TagInstanceAction(self.session, self.config)
        self.isolate_instance = IsolateInstanceAction(self.session, self.config)
        self.quarantine_profile = QuarantineInstanceProfileAction(
            self.session, self.config
        )
        self.create_snapshots = CreateSnapshotAction(self.session, self.config)
        self.enrich_finding = EnrichFindingWithInstanceMetadataAction(
            self.session, self.config
        )
        self.terminate_instance = TerminateInstanceAction(self.session, self.config)
        self.block_ip = BlockMaliciousIpAction(self.session, self.config)
        self.remove_rule = RemovePublicAccessAction(self.session, self.config)

    def _run_compromise_workflow(
        self, event: GuardDutyEvent, playbook_name: str
    ) -> PlaybookResult:
        """
        The compromised instance workflow was originally its own self-sufficient
        playbook. But, after development later EC2 findings showed to require
        conditional logic to dictate whether a different action was taken. Adding
        this full functionality to the base class ensured any playbook could
        call the compromise workflow "If" a certain condition in their playbook
        was met.

        :param event: the GuardDutyEvent json object
        :param playbook_name: string representing the playbooks name.
        :return: a PlaybookResult object containing the status of the steps taken
            and any detailed information.

        :meta private:
        """
        results: List[ActionResult] = []
        enriched_data = None

        # Step 1: Tag the instance with special tags.
        result = self.tag_instance.execute(event, playbook_name=playbook_name)
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

        logger.info(f"Playbook execution finished for {playbook_name}.")

        return {"action_results": results, "enriched_data": enriched_data}
