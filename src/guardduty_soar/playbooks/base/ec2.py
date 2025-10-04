import logging

from guardduty_soar.actions.ec2.enrich import \
    EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.quarantine import \
    QuarantineInstanceProfileAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.config import AppConfig
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import GuardDutyEvent
from guardduty_soar.playbook_registry import BasePlaybook

logger = logging.getLogger(__name__)


class EC2BasePlaybook(BasePlaybook):
    """
    An intermediate base class for all playbooks that respond to EC2 findings.

    Inherits the boto3 Session() from BasePlaybook and initializes all relevant
    EC2 action classes.
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

    def _run_compromise_workflow(self, event: GuardDutyEvent, playbook_name: str):
        # Step 1: Tag the instance with special tags.
        tagging_result = self.tag_instance.execute(
            event, playbook_name=self.__class__.__name__
        )
        if tagging_result["status"] == "error":
            # tagging failed
            error_details = tagging_result["details"]
            logger.error(f"Action 'tag_instance' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"TagInstanceAction failed: {error_details}."
            )
        logger.info("Successfully tagged instance.")

        # Step 2: Isolate the instance with a quarantined SG. Ideally
        # the security group should not have any inbound/outbound rules, and
        # all other security groups previously used by the instance are removed.
        isolate_result = self.isolate_instance.execute(event, config=self.config)
        if isolate_result["status"] == "error":
            # Isolation failed
            error_details = isolate_result["details"]
            logger.error(f"Action 'isolate_instance' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"IsolateInstanceAction failed: {error_details}."
            )
        logger.info("Successfully isolated instance.")

        # Step 3: Attach a deny all policy to the IAM instance profile associated
        # with the instance. We check if there is an instance profile, if there
        # isn't we return success and move on.
        quarantine_result = self.quarantine_profile.execute(event, config=self.config)
        if quarantine_result["status"] == "error":
            # Quarantine failed
            error_details = quarantine_result["details"]
            logger.error(f"Action 'quarantine_profile' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"QuarantineInstanceProfileAction failed: {error_details}."
            )
        logger.info("Successfully quarantined instance.")

        # Step 4: Create snapshots of all attached EBS volumes. Programmatically
        # checks for number and if any exists and iterates over them all. As we
        # do not know if/where any malicious activity could be nested in the
        # volumes. Appropriate tags are added as part of the call to
        # create_snapshot boto3 command.
        snapshot_result = self.create_snapshots.execute(event, config=self.config)
        if snapshot_result["status"] == "error":
            # Snapshotting failed
            error_details = snapshot_result["details"]
            logger.error(f"Action: 'create_snapshot' failed: {error_details}.")
            raise PlaybookActionFailedError(
                f"CreateSnapshotAction failed: {error_details}."
            )
        logger.info("Successfully took snapshot(s) of instances volumes.")
