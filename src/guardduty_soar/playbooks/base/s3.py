from guardduty_soar.actions.s3.enrich import EnrichS3BucketAction
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
        super().__init__(config)

        self.tag_s3_bucket = TagS3BucketAction(self.session, self.config)
        self.get_s3_enrichment = EnrichS3BucketAction(self.session, self.config)
