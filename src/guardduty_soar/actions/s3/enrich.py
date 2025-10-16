import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import S3BucketDetails, S3EnrichmentData

logger = logging.getLogger(__name__)


class EnrichS3BucketAction(BaseAction):
    """
    An action to enrich S3 bucket details from a GuardDuty finding. It gathers
    configuration details like policy, public access settings, encryption, and more.

    :param session: A boto3 Session object to build clients with.
    :param config: The Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.s3_client = self.session.client("s3")

    def _get_enrichment_data(self, bucket_name: str) -> Dict[str, Any]:
        """
        Helper to fetch all enrichment data for a single S3 bucket.

        :param bucket_name: The bucket name to gather information on.
        :return: A dictionary object that is used to create the S3EnrichedData model.

        :meta private:
        """
        data: Dict[str, Any] = {"name": bucket_name}

        # 1. Get Public Access Block Configuration
        try:
            data["public_access_block"] = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                logger.info(f"No Public Access Block for bucket: {bucket_name}.")
                data["public_access_block"] = None
            else:
                logger.error(
                    f"Failed to get public access block for {bucket_name}: {e}"
                )

        # 2. Get Bucket Policy
        try:
            data["policy"] = self.s3_client.get_bucket_policy(Bucket=bucket_name).get(
                "Policy"
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                logger.info(f"No bucket policy for bucket: {bucket_name}.")
                data["policy"] = None
            else:
                logger.error(f"Failed to get policy for {bucket_name}: {e}")

        # 3. Get Bucket Encryption
        try:
            data["encryption"] = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )["ServerSideEncryptionConfiguration"]
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                logger.info(f"No encryption configuration for bucket: {bucket_name}.")
                data["encryption"] = None
            else:
                logger.error(f"Failed to get encryption for {bucket_name}: {e}")

        # 4. Get Bucket Versioning
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            data["versioning"] = response.get("Status", "Not Configured")
        except ClientError as e:
            logger.error(f"Failed to get versioning for {bucket_name}: {e}")

        # 5. Get Bucket Logging
        try:
            data["logging"] = self.s3_client.get_bucket_logging(Bucket=bucket_name).get(
                "LoggingEnabled"
            )
        except ClientError as e:
            logger.error(f"Failed to get logging for {bucket_name}: {e}")

        # 6. Get Bucket Tags
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            data["tags"] = response.get("TagSet", [])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                logger.info(f"No tags for bucket: {bucket_name}.")
                data["tags"] = None
            else:
                logger.error(f"Failed to get tags for {bucket_name}: {e}")

        return data

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        enriched_buckets: List[Dict[str, Any]] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "S3Bucket":
            return {
                "status": "skipped",
                "details": "Resource type is not S3Bucket.",
            }

        bucket_details_list = resource_data.get("S3BucketDetails", [])
        if not bucket_details_list:
            return {
                "status": "skipped",
                "details": "No S3 buckets listed in this finding.",
            }

        for bucket_data in bucket_details_list:
            try:
                model = S3BucketDetails(**bucket_data, ResourceType="S3Bucket")
                bucket_name = model.bucket_name
                if not bucket_name:
                    continue

                logger.info(f"Enriching details for bucket: {bucket_name}")
                raw_enriched_data = self._get_enrichment_data(bucket_name)

                # Validate the final data structure against the Pydantic model
                validated_data = S3EnrichmentData(**raw_enriched_data).model_dump(
                    exclude_none=True
                )
                enriched_buckets.append(validated_data)

            except ValidationError as e:
                error_detail = f"Failed to validate enriched data for '{bucket_data.get('Name', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)
            except Exception as e:
                error_detail = f"An unknown error occurred while enriching '{bucket_data.get('Name', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Enriched: {len(enriched_buckets)} bucket(s).",
            }

        return {
            "status": "success",
            "details": enriched_buckets,
        }
