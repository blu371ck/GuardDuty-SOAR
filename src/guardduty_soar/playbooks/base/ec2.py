from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.playbook_registry import BasePlaybook


class EC2BasePlaybook(BasePlaybook):
    """
    An intermediate base class for all playbooks that respond to EC2 findings.

    Inherits the boto3 Session() from BasePlaybook and initializes all relevant
    EC2 action classes.
    """

    def __init__(self):
        super().__init__()
        self.tag_instance = TagInstanceAction(self.session)
