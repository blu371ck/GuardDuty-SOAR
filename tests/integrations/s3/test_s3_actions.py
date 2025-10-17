import dataclasses
import logging
import random
import string
import time

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.s3.block import S3BlockPublicAccessAction
from guardduty_soar.actions.s3.enrich import EnrichS3BucketAction
from guardduty_soar.actions.s3.tag import TagS3BucketAction

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_tag_s3_single_bucket_action_integration(
    temporary_s3_bucket, s3_finding_detail, real_app_config
):
    """
    Tests the TagS3BucketAction on a single response S3 bucket finding.
    """
    bucket_name = temporary_s3_bucket
    assert "guardduty-soar-test-bucket-" in bucket_name

    s3_finding_detail["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name

    session = boto3.Session()
    action = TagS3BucketAction(session, real_app_config)
    result = action.execute(s3_finding_detail, playbook_name="IntegrationTestPlaybook")

    assert result["status"] == "success"
    time.sleep(2)  # Allow tags to propagate

    s3_client = session.client("s3")
    tags = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    }
    assert "SOAR-Status" in tags and tags["SOAR-Status"] == "Remediation-In-Progress"


def test_tag_s3_multiple_bucket_action_integration(
    temporary_s3_bucket, s3_finding_multiple_buckets, real_app_config
):
    """
    Tests the TagS3BucketAction on a finding with multiple S3 buckets.
    """
    # Note: This test creates and cleans up two separate temporary buckets.
    s3_client = boto3.client("s3")
    bucket_name1 = temporary_s3_bucket

    # Create a second bucket manually for this test
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    bucket_name2 = f"guardduty-soar-test-bucket-{suffix}"
    s3_client.create_bucket(Bucket=bucket_name2)

    assert "guardduty-soar-test-bucket-" in bucket_name1
    assert "guardduty-soar-test-bucket-" in bucket_name2

    s3_finding_multiple_buckets["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name1
    s3_finding_multiple_buckets["Resource"]["S3BucketDetails"][1]["Name"] = bucket_name2

    session = boto3.Session()
    action = TagS3BucketAction(session, real_app_config)
    result = action.execute(
        s3_finding_multiple_buckets, playbook_name="IntegrationTestPlaybook"
    )

    assert result["status"] == "success"
    time.sleep(2)  # Allow tags to propagate

    tags1 = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name1)["TagSet"]
    }
    assert "SOAR-Status" in tags1 and tags1["SOAR-Status"] == "Remediation-In-Progress"

    tags2 = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name2)["TagSet"]
    }
    assert "SOAR-Status" in tags2 and tags2["SOAR-Status"] == "Remediation-In-Progress"

    # Clean up the manually created bucket
    s3_client.delete_bucket(Bucket=bucket_name2)


def test_enrich_s3_action_integration(
    temporary_s3_bucket, s3_finding_detail, real_app_config
):
    """
    Tests the EnrichS3BucketAction against a live S3 bucket with a known configuration.
    """
    session = boto3.Session()
    s3_client = session.client("s3")
    bucket_name = temporary_s3_bucket
    action = EnrichS3BucketAction(session, real_app_config)

    # Apply a known configuration to the live bucket for testing.
    s3_client.put_bucket_versioning(
        Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
    )
    time.sleep(2)  # Allow configuration to propagate.

    s3_finding_detail["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name
    result = action.execute(event=s3_finding_detail)

    assert result["status"] == "success"
    assert len(result["details"]) == 1

    enriched_data = result["details"][0]
    assert enriched_data["name"] == bucket_name
    assert enriched_data["versioning"] == "Enabled"
    assert "policy" not in enriched_data


def test_block_s3_public_access_action_integration(
    temporary_s3_bucket, s3_finding_detail, real_app_config
):
    """
    Tests the S3BlockPublicAccessAction against a live S3 bucket.
    """
    #  A live S3 bucket and the action is enabled in the config
    session = boto3.Session()
    s3_client = session.client("s3")
    bucket_name = temporary_s3_bucket

    # Create a new config instance with allow_s3_public_block set to True
    test_config = dataclasses.replace(real_app_config, allow_s3_public_block=True)

    # Update the finding to point to our live bucket
    s3_finding_detail["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name

    # Use the new, non-frozen config for this action
    action = S3BlockPublicAccessAction(session, test_config)

    # The action is executed
    result = action.execute(event=s3_finding_detail)
    assert result["status"] == "success"
    time.sleep(2)  # Allow setting to propagate

    # The public access block should be applied correctly
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        assert config["BlockPublicAcls"] is True
        assert config["IgnorePublicAcls"] is True
        assert config["BlockPublicPolicy"] is True
        assert config["RestrictPublicBuckets"] is True
    except ClientError as e:
        pytest.fail(f"Failed to get public access block settings. Error: {e}")
