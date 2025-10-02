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
        # For each child of the BasePlaybook class we will register all actions 
        # applicable to all playbooks regarding that type. For instance, this is
        # going to store all actions applicable to playbooks that are applicable to
        # EC2 reports/findings.
        self.tag_instance = TagInstanceAction(self.session)
