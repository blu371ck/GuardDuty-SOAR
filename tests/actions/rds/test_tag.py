from unittest.mock import ANY, MagicMock, call

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.rds.tag import TagRdsInstanceAction


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and a mock RDS client."""
    mock_session = MagicMock()
    mock_rds_client = MagicMock()
    mock_session.client.return_value = mock_rds_client
    return mock_session, mock_rds_client


@pytest.fixture
def tag_rds_action(mock_boto_session, mock_app_config):
    """Initializes the TagRdsInstanceAction with mock dependencies."""
    session, _ = mock_boto_session
    return TagRdsInstanceAction(session, mock_app_config)


def test_tag_rds_instance_success_single(
    tag_rds_action, mock_boto_session, rds_finding_detail
):
    """
    GIVEN a finding with a single RDS instance.
    WHEN the tag action is executed.
    THEN it should successfully tag that instance.
    """
    _, mock_rds_client = mock_boto_session
    instance_id = "test-db-instance-1"
    expected_arn = "arn:aws:rds:us-east-1:1234567891234:db:test-db-instance-1"

    result = tag_rds_action.execute(event=rds_finding_detail)

    assert result["status"] == "success"
    mock_rds_client.add_tags_to_resource.assert_called_once_with(
        ResourceName=expected_arn, Tags=ANY
    )


def test_tag_rds_instance_success_multiple(
    tag_rds_action, mock_boto_session, rds_finding_multiple_instances
):
    """
    GIVEN a finding with multiple RDS instances.
    WHEN the tag action is executed.
    THEN it should successfully tag both instances.
    """
    _, mock_rds_client = mock_boto_session
    expected_arn_1 = "arn:aws:rds:us-east-1:1234567891234:db:test-db-instance-1"
    expected_arn_2 = "arn:aws:rds:us-east-1:1234567891234:db:test-db-instance-2"

    result = tag_rds_action.execute(event=rds_finding_multiple_instances)

    assert result["status"] == "success"
    assert mock_rds_client.add_tags_to_resource.call_count == 2
    mock_rds_client.add_tags_to_resource.assert_has_calls(
        [
            call(ResourceName=expected_arn_1, Tags=ANY),
            call(ResourceName=expected_arn_2, Tags=ANY),
        ],
        any_order=True,
    )


def test_tag_rds_instance_skipped_if_no_instances(tag_rds_action, mock_boto_session):
    """
    GIVEN a finding with no RDS instances in the details.
    WHEN the tag action is executed.
    THEN it should be skipped.
    """
    _, mock_rds_client = mock_boto_session
    empty_finding = {"Resource": {"RdsDbInstanceDetails": []}}

    result = tag_rds_action.execute(event=empty_finding)

    assert result["status"] == "skipped"
    mock_rds_client.add_tags_to_resource.assert_not_called()


def test_tag_rds_instance_handles_client_error(
    tag_rds_action, mock_boto_session, rds_finding_detail
):
    """
    GIVEN the boto3 RDS client raises an error.
    WHEN the tag action is executed.
    THEN it should return an 'error' status.
    """
    _, mock_rds_client = mock_boto_session
    mock_rds_client.add_tags_to_resource.side_effect = ClientError(
        error_response={"Error": {"Code": "DBInstanceNotFound"}},
        operation_name="AddTagsToResource",
    )

    result = tag_rds_action.execute(event=rds_finding_detail)

    assert result["status"] == "error"
    assert "DBInstanceNotFound" in result["details"]
