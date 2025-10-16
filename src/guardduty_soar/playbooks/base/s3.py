from guardduty_soar.actions.s3.tag import TagS3BucketAction
from guardduty_soar.config import AppConfig
from guardduty_soar.playbooks.base.iam import IamBasePlaybook


class S3BasePlaybook(IamBasePlaybook):
    """
    An abstract base class for S3-related playbooks.

    It inherits from IamBasePlaybook to gain access to all IAM-related
    actions, as S3 findings often involve an IAM principal as the actor.
    It also initializes all S3-specific actions.

    :param config: the Applications configurations.
    """

    def __init__(self, config: AppConfig):
        # First, initialize the parent class (IamBasePlaybook) to set up all IAM actions
        super().__init__(config)

        # Now, initialize all S3-specific actions
        self.tag_s3_bucket = TagS3BucketAction(self.session, self.config)
        # self.enrich_s3_finding = EnrichS3FindingAction(session, config)
        # self.remediate_public_access = RemediateS3PublicAccessAction(session, config)
