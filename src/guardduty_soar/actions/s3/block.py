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


class S3BlockPublicAccessAction(BaseAction):
    """
    Applies a "block all public access" policy to S3 buckets in a finding.

    This is an optional remediation action controlled by the configuration
    setting `allow_s3_public_block`.

    :param session: A Boto3 Session object to create clients with.
    :param config: The application's configuration.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.s3_client = self.session.client("s3")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Executes the action to apply the public access block.

        It will parse all S3 buckets from the event and attempt to apply the
        block to each one individually.
        """
        if not self.config.allow_s3_public_block:
            details = (
                "Action skipped: allow_s3_public_block is disabled in configuration."
            )
            logger.warning(details)
            return {"status": "skipped", "details": details}

        blocked_buckets: List[str] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "S3Bucket":
            return {"status": "skipped", "details": "Resource type is not S3Bucket."}

        bucket_details_list = resource_data.get("S3BucketDetails", [])
        if not bucket_details_list:
            return {
                "status": "skipped",
                "details": "No S3 buckets listed in this finding.",
            }

        for bucket_data in bucket_details_list:
            try:
                # We need to check if any of the s3 buckets in the finding are
                # directory buckets, as we cannot apply public access block policy
                # in boto3.
                if bucket_data.get("Type") == "S3DirectoryBucket":
                    logger.warning(
                        f"Skipping block public access for bucket {bucket_data.get("Name")} because it is a directory bucket."
                    )
                    # move on to the next bucket
                    continue

                # Use the Pydantic model for validation
                model = S3BucketDetails(**bucket_data, ResourceType="S3Bucket")
                bucket_name = model.bucket_name
                if not bucket_name:
                    continue

                logger.warning(
                    f"ACTION: Applying block public access to bucket: {bucket_name}"
                )
                self.s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                )
                blocked_buckets.append(bucket_name)

            except ValidationError as e:
                error_detail = f"Failed to validate bucket data '{bucket_data.get('Name', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)
            except ClientError as e:
                error_detail = f"Failed to block public access for '{bucket_data.get('Name', 'Unknown')}'. Error: {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Blocked: {blocked_buckets}. Errors: {errors}",
            }

        return {
            "status": "success",
            "details": f"Successfully blocked public access for {len(blocked_buckets)} bucket(s): {blocked_buckets}",
        }
