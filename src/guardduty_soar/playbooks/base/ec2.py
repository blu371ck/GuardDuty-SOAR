import logging

from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
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

        logger.info(f"Successfully ran playbook on instance:")
