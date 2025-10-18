import logging

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction
from guardduty_soar.actions.ec2.enrich import EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.quarantine import QuarantineInstanceProfileAction
from guardduty_soar.actions.ec2.remove import RemovePublicAccessAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction
from guardduty_soar.config import AppConfig
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
