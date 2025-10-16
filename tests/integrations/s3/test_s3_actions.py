import logging
import time

import boto3
import pytest
from botocore.exceptions import ClientError

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
    bucket_name1 = temporary_s3_bucket
    bucket_name2 = temporary_s3_bucket

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

    s3_client = session.client("s3")
    tags = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name1)["TagSet"]
    }

    assert "SOAR-Status" in tags and tags["SOAR-Status"] == "Remediation-In-Progress"

    tags = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name2)["TagSet"]
    }

    assert "SOAR-Status" in tags and tags["SOAR-Status"] == "Remediation-In-Progress"
