from unittest.mock import MagicMock

import boto3
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.s3.tag import TagS3BucketAction


def test_tag_single_bucket_success(s3_finding_detail, mock_app_config):
    """
    Tests the TagS3BucketAction using a botocore stubber to mock the AWS API.
    """
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    s3_bucket = s3_finding_detail["Resource"]["S3BucketDetails"][0]["Name"]
    expected_params = {
        "Bucket": s3_bucket,
        "Tagging": {
            "TagSet": [
                {"Key": "GUARDDUTY-SOAR-ID", "Value": s3_finding_detail["Id"]},
                {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"},
                {"Key": "SOAR-Action-Time-UTC", "Value": ANY},
                {"Key": "SOAR-Finding-Type", "Value": s3_finding_detail["Type"]},
                {"Key": "SOAR-Finding-Severity", "Value": "HIGH"},
                {"Key": "SOAR-Playbook", "Value": "TestPlaybook"},
            ]
        },
    }

    stubber.add_response("put_bucket_tagging", {}, expected_params)

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = s3_client

        action = TagS3BucketAction(mock_session, mock_app_config)
        result = action.execute(s3_finding_detail, playbook_name="TestPlaybook")

        assert result["status"] == "success"
        assert "Successfully tagged 1 bucket(s): " in result["details"]
    stubber.assert_no_pending_responses()


def test_tag_multiple_bucket_success(s3_finding_multiple_buckets, mock_app_config):
    """
    Tests the scenario where multiple buckets are in the GuardDuty finding.
    """

    s3_client = boto3.client("s3")
    action = TagS3BucketAction(boto3.Session(), mock_app_config)
    action.s3_client = s3_client

    bucket1_name = s3_finding_multiple_buckets["Resource"]["S3BucketDetails"][0]["Name"]
    bucket2_name = s3_finding_multiple_buckets["Resource"]["S3BucketDetails"][1]["Name"]

    with Stubber(s3_client) as stubber:
        tag_set = [
            {"Key": "GUARDDUTY-SOAR-ID", "Value": s3_finding_multiple_buckets["Id"]},
            {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"},
            {"Key": "SOAR-Action-Time-UTC", "Value": ANY},
            {"Key": "SOAR-Finding-Type", "Value": s3_finding_multiple_buckets["Type"]},
            {"Key": "SOAR-Finding-Severity", "Value": "HIGH"},
            {"Key": "SOAR-Playbook", "Value": "TestPlaybook"},
        ]

        stubber.add_response(
            "put_bucket_tagging",
            {},
            {"Bucket": bucket1_name, "Tagging": {"TagSet": tag_set}},
        )

        # Expect the second call.
        stubber.add_response(
            "put_bucket_tagging",
            {},
            {"Bucket": bucket2_name, "Tagging": {"TagSet": tag_set}},
        )

        result = action.execute(
            s3_finding_multiple_buckets, playbook_name="TestPlaybook"
        )

        assert result["status"] == "success"
        assert "Successfully tagged 2 bucket(s): " in result["details"]
        stubber.assert_no_pending_responses()
