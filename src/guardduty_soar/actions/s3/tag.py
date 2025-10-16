import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class TagS3BucketAction(BaseAction):
    """
    An action to tag S3 buckets. This indicates the a bucket was a potential
    target of malicious activities.

    :param session: a Boto3 Session object to make clients with.
    :param config: the Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.s3_client = self.session.client("s3")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")

        try:
            buckets = event["Resource"].get("S3BucketDetails", [])
            if not buckets:
                return {
                    "status": "skipped",
                    "details": "No S3 buckets listed in this finding.",
                }

            logger.info(f"Found {len(buckets)} bucket(s) in this finding.")
            for bucket in buckets:
                bucket_name = bucket["Name"]
                logger.warning(f"ACTION: Tagging bucket: {bucket_name}.")
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={"TagSet": self._tags_to_apply(event, playbook_name)},
                )
                logger.info(f"Successfully tagged bucket: {bucket_name}.")

            logger.info("Successfully finished adding tags to bucket(s).")

            return {"status": "success", "details": buckets}
        except ClientError as e:
            details = f"Failed to add tags to bucket(s). Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
