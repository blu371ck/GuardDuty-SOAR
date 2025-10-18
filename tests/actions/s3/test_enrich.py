from unittest.mock import MagicMock, call, patch

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.s3.enrich import EnrichS3BucketAction


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and client for S3."""
    mock_session = MagicMock()
    mock_s3_client = MagicMock()
    mock_session.client.return_value = mock_s3_client
    return mock_session, mock_s3_client


@pytest.fixture
def enrich_s3_action(mock_boto_session, mock_app_config):
    """Initializes the EnrichS3BucketAction with mock dependencies."""
    session, _ = mock_boto_session
    return EnrichS3BucketAction(session, mock_app_config)


def configure_mock_s3_client(mock_s3_client, bucket_name="example-bucket1"):
    """Helper function to configure mock return values for S3 API calls."""
    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
    }
    mock_s3_client.get_bucket_policy.return_value = {
        "Policy": '{"Version": "2012-10-17"}'
    }
    mock_s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }
    }
    mock_s3_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
    mock_s3_client.get_bucket_logging.return_value = {
        "LoggingEnabled": {"TargetBucket": "logging-bucket"}
    }
    mock_s3_client.get_bucket_tagging.return_value = {
        "TagSet": [{"Key": "Test", "Value": "True"}]
    }


def test_enrich_s3_single_bucket_success(
    enrich_s3_action, mock_boto_session, s3_finding_detail
):
    """
    GIVEN an S3 finding with a single bucket.
    WHEN the enrich action is executed successfully.
    THEN it should return a 'success' status with one enriched bucket in the details.
    """
    _, mock_s3_client = mock_boto_session
    configure_mock_s3_client(mock_s3_client)

    result = enrich_s3_action.execute(event=s3_finding_detail)

    assert result["status"] == "success"
    assert len(result["details"]) == 1

    enriched_data = result["details"][0]
    assert enriched_data["name"] == "example-bucket1"
    assert "public_access_block" in enriched_data
    assert "policy" in enriched_data
    assert "encryption" in enriched_data
    assert enriched_data["versioning"] == "Enabled"

    # Verify all expected boto3 calls were made
    mock_s3_client.get_public_access_block.assert_called_once_with(
        Bucket="example-bucket1"
    )
    mock_s3_client.get_bucket_policy.assert_called_once_with(Bucket="example-bucket1")
    mock_s3_client.get_bucket_encryption.assert_called_once_with(
        Bucket="example-bucket1"
    )


def test_enrich_s3_multiple_buckets_success(
    enrich_s3_action, mock_boto_session, s3_finding_multiple_buckets
):
    """
    GIVEN an S3 finding with two buckets.
    WHEN the enrich action is executed successfully.
    THEN it should return a 'success' status with two enriched buckets in the details.
    """
    _, mock_s3_client = mock_boto_session
    configure_mock_s3_client(mock_s3_client)  # This mock works for any bucket name

    result = enrich_s3_action.execute(event=s3_finding_multiple_buckets)

    assert result["status"] == "success"
    assert len(result["details"]) == 2
    assert result["details"][0]["name"] == "example-bucket1"
    assert result["details"][1]["name"] == "example-bucket2"

    # Verify boto3 calls were made for both buckets
    assert mock_s3_client.get_bucket_versioning.call_count == 2
    mock_s3_client.get_bucket_versioning.assert_has_calls(
        [call(Bucket="example-bucket1"), call(Bucket="example-bucket2")], any_order=True
    )


def test_enrich_s3_handles_missing_configurations(
    enrich_s3_action, mock_boto_session, s3_finding_detail
):
    """
    GIVEN an S3 bucket with no policy or tags.
    WHEN the enrich action is executed.
    THEN it should still succeed and gracefully handle the 'Not Found' ClientErrors.
    """
    _, mock_s3_client = mock_boto_session
    configure_mock_s3_client(mock_s3_client)

    # Configure specific methods to raise "Not Found" errors
    mock_s3_client.get_bucket_policy.side_effect = ClientError(
        error_response={"Error": {"Code": "NoSuchBucketPolicy"}},
        operation_name="GetBucketPolicy",
    )
    mock_s3_client.get_bucket_tagging.side_effect = ClientError(
        error_response={"Error": {"Code": "NoSuchTagSet"}},
        operation_name="GetBucketTagging",
    )

    result = enrich_s3_action.execute(event=s3_finding_detail)

    assert result["status"] == "success"
    assert len(result["details"]) == 1

    enriched_data = result["details"][0]
    # Verify the keys for the failed calls are not present in the final validated output
    assert "policy" not in enriched_data
    assert "tags" not in enriched_data
    # Verify other data was still fetched
    assert "encryption" in enriched_data


def test_enrich_s3_skips_non_s3_finding(
    enrich_s3_action, mock_boto_session, guardduty_finding_detail
):
    """
    GIVEN a non-S3 finding (e.g., an EC2 finding).
    WHEN the enrich S3 action is executed.
    THEN it should return a 'skipped' status and not call any S3 APIs.
    """
    _, mock_s3_client = mock_boto_session

    # Pass the EC2 finding fixture
    result = enrich_s3_action.execute(event=guardduty_finding_detail)

    assert result["status"] == "skipped"
    assert "Resource type is not S3Bucket" in result["details"]

    # Ensure no S3 API calls were attempted
    mock_s3_client.get_public_access_block.assert_not_called()
    mock_s3_client.get_bucket_policy.assert_not_called()


def test_enrich_s3_skips_directory_bucket(enrich_s3_action, s3_finding_mixed_buckets):
    """
    GIVEN a finding with both standard and directory buckets.
    WHEN the enrich action is executed.
    THEN it should only attempt to enrich the standard buckets.
    """
    # We patch the internal helper method to see what it gets called with
    with patch.object(enrich_s3_action, "_get_enrichment_data") as mock_get_data:
        # To prevent errors, have the mock return a valid structure
        mock_get_data.return_value = {"name": "mocked"}

        result = enrich_s3_action.execute(event=s3_finding_mixed_buckets)

    assert result["status"] == "success"
    # Verify the helper was only called for the two standard buckets
    assert mock_get_data.call_count == 2
    mock_get_data.assert_has_calls(
        [call("example-bucket1"), call("example-bucket2")], any_order=True
    )
