from unittest.mock import MagicMock, call

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.s3.block import S3BlockPublicAccessAction


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and a mock S3 client."""
    mock_session = MagicMock()
    mock_s3_client = MagicMock()
    mock_session.client.return_value = mock_s3_client
    return mock_session, mock_s3_client


@pytest.fixture
def block_s3_action(mock_boto_session, mock_app_config):
    """Initializes the S3BlockPublicAccessAction with mock dependencies."""
    session, _ = mock_boto_session
    return S3BlockPublicAccessAction(session, mock_app_config)


def test_block_public_access_success_single_bucket(
    block_s3_action, mock_boto_session, mock_app_config, s3_finding_detail
):
    """
    GIVEN an S3 finding with a single bucket and the action is enabled.
    WHEN the action is executed.
    THEN it should succeed and call put_public_access_block for that bucket.
    """
    _, mock_s3_client = mock_boto_session
    mock_app_config.allow_s3_public_block = True

    result = block_s3_action.execute(event=s3_finding_detail)

    assert result["status"] == "success"
    assert (
        "Successfully blocked public access for 1 bucket(s): ['example-bucket1']"
        in result["details"]
    )
    mock_s3_client.put_public_access_block.assert_called_once_with(
        Bucket="example-bucket1",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def test_block_public_access_success_multiple_buckets(
    block_s3_action, mock_boto_session, mock_app_config, s3_finding_multiple_buckets
):
    """
    GIVEN an S3 finding with multiple buckets and the action is enabled.
    WHEN the action is executed.
    THEN it should succeed and call put_public_access_block for each bucket.
    """
    _, mock_s3_client = mock_boto_session
    mock_app_config.allow_s3_public_block = True

    result = block_s3_action.execute(event=s3_finding_multiple_buckets)

    assert result["status"] == "success"
    assert "Successfully blocked public access for 2 bucket(s)" in result["details"]
    assert mock_s3_client.put_public_access_block.call_count == 2

    # FIX: Define the exact configuration dictionary that the action uses.
    expected_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    # FIX: Use the specific dictionary in the assertion instead of MagicMock().
    mock_s3_client.put_public_access_block.assert_has_calls(
        [
            call(
                Bucket="example-bucket1", PublicAccessBlockConfiguration=expected_config
            ),
            call(
                Bucket="example-bucket2", PublicAccessBlockConfiguration=expected_config
            ),
        ],
        any_order=True,
    )


def test_block_public_access_disabled_in_config(
    block_s3_action, mock_boto_session, mock_app_config, s3_finding_detail
):
    """
    GIVEN the allow_s3_public_block configuration is False.
    WHEN the action is executed.
    THEN it should return a 'skipped' status.
    """
    _, mock_s3_client = mock_boto_session
    mock_app_config.allow_s3_public_block = False

    result = block_s3_action.execute(event=s3_finding_detail)

    assert result["status"] == "skipped"
    assert "disabled in configuration" in result["details"]
    mock_s3_client.put_public_access_block.assert_not_called()


def test_block_public_access_skips_non_s3_finding(
    block_s3_action, mock_boto_session, mock_app_config, guardduty_finding_detail
):
    """
    GIVEN a non-S3 GuardDuty finding.
    WHEN the action is executed.
    THEN it should return a 'skipped' status.
    """
    _, mock_s3_client = mock_boto_session
    mock_app_config.allow_s3_public_block = True

    result = block_s3_action.execute(event=guardduty_finding_detail)

    assert result["status"] == "skipped"
    assert "Resource type is not S3Bucket" in result["details"]
    mock_s3_client.put_public_access_block.assert_not_called()


def test_block_public_access_handles_client_error(
    block_s3_action, mock_boto_session, mock_app_config, s3_finding_detail
):
    """
    GIVEN the boto3 client raises an error.
    WHEN the action is executed.
    THEN it should return an 'error' status.
    """
    _, mock_s3_client = mock_boto_session
    mock_app_config.allow_s3_public_block = True

    mock_s3_client.put_public_access_block.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDenied"}},
        operation_name="PutPublicAccessBlock",
    )

    result = block_s3_action.execute(event=s3_finding_detail)

    assert result["status"] == "error"
    assert "Completed with 1 error(s)" in result["details"]
    assert "AccessDenied" in result["details"]
