import logging
from typing import List

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import S3BucketDetails

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
        tagged_buckets: List[str] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "S3Bucket":
            return {"status": "skipped", "details": "Resource type is not S3bucket."}

        bucket_details_list = resource_data.get("S3BucketDetails", [])
        if not bucket_details_list:
            return {
                "status": "skipped",
                "details": "No S3 buckets listed in this finding.",
            }

        logger.info(f"Found {len(bucket_details_list)} bucket(s) in this finding.")

        for bucket_data in bucket_details_list:
            try:
                # Create a validated Pydantic model fo reach bucket in the loop
                model = S3BucketDetails(**bucket_data, ResourceType="S3Bucket")
                bucket_name = model.bucket_name
                if not bucket_name:
                    continue

                logger.warning(f"ACTION: Tagging bucket: {bucket_name}.")
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={"TagSet": self._tags_to_apply(event, playbook_name)},
                )
                logger.info(f"Successfully tagged bucket: {bucket_name}.")
                tagged_buckets.append(bucket_name)
            except ValidationError as e:
                details = f"Failed to validate bucket data '{bucket_data.get('Name', 'Unknown')}: {e}."
                logger.error(details)
                return {"status": "error", "details": details}
            except ClientError as e:
                details = f"Failed to add tags to bucket(s). Error: {e}."
                logger.error(details)
                return {"status": "error", "details": details}
            except Exception as e:
                details = f"An unknown error occurred: {e}."
                logger.error(details)
                return {"status": "error", "details": details}

        logger.info("Successfully finished adding tags to bucket(s).")

        return {
            "status": "success",
            "details": f"Successfully tagged {len(tagged_buckets)} bucket(s): {tagged_buckets}.",
        }
