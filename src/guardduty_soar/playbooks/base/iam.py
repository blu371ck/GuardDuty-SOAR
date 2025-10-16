import logging

from guardduty_soar.actions.iam.analyze import AnalyzePermissionsAction
from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction
from guardduty_soar.actions.iam.history import GetCloudTrailHistoryAction
from guardduty_soar.actions.iam.identify import IdentifyIamPrincipalAction
from guardduty_soar.actions.iam.tag import TagIamPrincipalAction
from guardduty_soar.config import AppConfig
from guardduty_soar.playbook_registry import BasePlaybook

logger = logging.getLogger(__name__)


class IamBasePlaybook(BasePlaybook):
    """
    An intermediate base class for all playbooks that respond to IAM findings.
    (Minus two that belong to ec2 credential theft, which are in
    EC2InstanceCompromisePlaybook).

    Inherits the boto3 session from BasePlaybook and initializes all relevant IAM
    action classes.

    :param config: the Applications configurations.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config)
        # For each child of the BasePlaybook class we will register all actions
        # applicable to all playbooks regarding that type. This allows them
        # to be used by children without needing to import the code in multiple
        # places.
        self.tag_principal = TagIamPrincipalAction(self.session, self.config)
        self.identify_principal = IdentifyIamPrincipalAction(self.session, self.config)
        self.get_history = GetCloudTrailHistoryAction(self.session, self.config)
        self.get_details = GetIamPrincipalDetailsAction(self.session, self.config)
        self.analyze_permissions = AnalyzePermissionsAction(self.session, self.config)
