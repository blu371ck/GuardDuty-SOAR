import logging

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction
from guardduty_soar.actions.iam.analyze import AnalyzePermissionsAction
from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction
from guardduty_soar.actions.iam.history import GetCloudTrailHistoryAction
from guardduty_soar.actions.iam.quarantine import QuarantineIamPrincipalAction
from guardduty_soar.actions.iam.tag import TagIamPrincipalAction
from guardduty_soar.actions.rds.tag import TagRdsInstanceAction
from guardduty_soar.config import AppConfig
from guardduty_soar.playbook_registry import BasePlaybook

logger = logging.getLogger(__name__)


class RdsBasePlaybook(BasePlaybook):
    """
    The base playbook for all RDS-related findings.

    It is initialized with a set of common RDS, EC2, and IAM actions
    that are likely to be used by its child playbooks.

    :param config: the Applications configurations.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config)

        # from Ec2
        self.block_ip = BlockMaliciousIpAction(self.session, self.config)

        # from IAM
        self.tag_principal = TagIamPrincipalAction(self.session, self.config)
        self.get_details = GetIamPrincipalDetailsAction(self.session, self.config)
        self.get_history = GetCloudTrailHistoryAction(self.session, self.config)
        self.analyze_permissions = AnalyzePermissionsAction(self.session, self.config)
        self.quarantine_principal = QuarantineIamPrincipalAction(
            self.session, self.config
        )

        # new RDS
        self.tag_instance = TagRdsInstanceAction(self.session, self.config)
