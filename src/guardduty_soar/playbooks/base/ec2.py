import logging

from guardduty_soar.actions.ec2.enrich import \
    EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.quarantine import \
    QuarantineInstanceProfileAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction
from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
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
        self.terminate_instance = TerminateInstanceAction(self.session, self.config)
        self.notify_ses = SendSESNotificationAction(self.session, self.config)

    def _run_compromise_workflow(self, event: GuardDutyEvent, playbook_name: str):
        # Step 0: Send initial notification(s)
        self.notify_ses.execute(
            event, playbook_name=playbook_name, template_type="starting"
        )

        enriched_finding = None
        final_status_message = (
            "Playbook completed successfully. All remediation actions were successful."
        )
        final_status_emoji = "✅"
        actions_summary = []

        try:
            # Step 1: Tag the instance with special tags.
            tagging_result = self.tag_instance.execute(
                event, playbook_name=playbook_name
            )
            if tagging_result["status"] == "error":
                # tagging failed
                error_details = tagging_result["details"]
                logger.error(f"Action 'tag_instance' failed: {error_details}.")
                raise PlaybookActionFailedError(
                    f"TagInstanceAction failed: {error_details}."
                )
            actions_summary.append(f"TagInstance: {tagging_result['status'].upper()}")
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
            actions_summary.append(
                f"IsolateInstance: {isolate_result['status'].upper()}"
            )
            logger.info("Successfully isolated instance.")

            # Step 3: Attach a deny all policy to the IAM instance profile associated
            # with the instance. We check if there is an instance profile, if there
            # isn't we return success and move on.
            quarantine_result = self.quarantine_profile.execute(
                event, config=self.config
            )
            if quarantine_result["status"] == "error":
                # Quarantine failed
                error_details = quarantine_result["details"]
                logger.error(f"Action 'quarantine_profile' failed: {error_details}.")
                raise PlaybookActionFailedError(
                    f"QuarantineInstanceProfileAction failed: {error_details}."
                )
            actions_summary.append(
                f"QuarantineInstance: {quarantine_result['status'].upper()}"
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
            actions_summary.append(
                f"SnapshotInstance: {snapshot_result['status'].upper()}"
            )
            logger.info("Successfully took snapshot(s) of instances volumes.")

            # Step 5: Enrich the GuardDuty finding event with metadata about the
            # compromised EC2 instance. This data is then passed through to the end-user
            # via the notification methods coming up.
            enrichment_result = self.enrich_finding.execute(event, config=self.config)
            if enrichment_result["status"] == "success":
                enriched_finding = enrichment_result["details"]
            actions_summary.append(
                f"EnrichFinding: {enrichment_result['status'].upper()}"
            )
            logger.info("Successfully performed enrichment step.")

            # Step 6: Terminate the instance, if user has selected for destructive actions.
            terminate_result = self.terminate_instance.execute(
                event, config=self.config
            )
            if terminate_result["status"] == "error":
                # Termination failed
                error_details = terminate_result["details"]
                logger.error(f"Action: 'terminate_instance' failed: {error_details}.")
                raise PlaybookActionFailedError(
                    f"TerminateInstanceAction failed: {error_details}."
                )
            actions_summary.append(
                f"TerminateInstance: {terminate_result['status'].upper()}"
            )
            logger.info("Successfully terminated")

        except PlaybookActionFailedError as e:
            logger.critical(f"A critical action failed in {playbook_name}: {e}.")
            final_status_message = f"PLAYBOOK FAILED: {e}"
            final_status_emoji = "❌"

        finally:
            # Regardless of what happens above, we need to send the final notification so
            # end users know the success/failed status with more information.
            notification_data = enriched_finding if enriched_finding else event

            # Step 7: We send notifications again now that the playbook is completed.
            # We provide much more information as well as what steps were taken.
            self.notify_ses.execute(
                notification_data,
                playbook_name=playbook_name,
                template_type="complete",
                final_status_emoji=final_status_emoji,
                actions_summary="\n".join(f"- {s}" for s in actions_summary),
                final_status_message=final_status_message,
            )

            logger.info(f"Playbook execution finished for {playbook_name}.")
