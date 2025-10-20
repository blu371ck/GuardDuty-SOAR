from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.rds.modify import ModifyRdsPublicAccessAction


@pytest.fixture
def mock_boto3_session():
    """Provides a mock boto3 session and its RDS client."""
    session = MagicMock()
    mock_rds_client = MagicMock()
    session.client.return_value = mock_rds_client
    return session, mock_rds_client


def test_execute_success_when_enabled(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests that the action calls modify_db_instance when the config is enabled.
    """
    session, mock_rds_client = mock_boto3_session
    mock_app_config.allow_revoke_public_access_rds = True
    action = ModifyRdsPublicAccessAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "success"
    mock_rds_client.modify_db_instance.assert_called_once_with(
        DBInstanceIdentifier="test-db-instance-1",
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )


def test_execute_skipped_when_disabled(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests that the action is skipped if the controlling config flag is False.
    """
    session, mock_rds_client = mock_boto3_session
    mock_app_config.allow_revoke_public_access_rds = False  # Explicitly disable
    action = ModifyRdsPublicAccessAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "skipped"
    assert "Configuration" in result["details"]
    mock_rds_client.modify_db_instance.assert_not_called()


def test_execute_skipped_for_non_rds_finding(
    mock_boto3_session, mock_app_config, s3_finding_detail
):
    """
    Tests that the action is skipped for non-DBInstance resource types.
    """
    session, mock_rds_client = mock_boto3_session
    mock_app_config.allow_revoke_public_access_rds = True
    action = ModifyRdsPublicAccessAction(session, mock_app_config)

    result = action.execute(event=s3_finding_detail)

    assert result["status"] == "skipped"
    assert "Resource type is not DBInstance" in result["details"]
    mock_rds_client.modify_db_instance.assert_not_called()


def test_execute_handles_clienterror(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests that the action returns an error status if the boto3 call fails.
    """
    session, mock_rds_client = mock_boto3_session
    mock_app_config.allow_revoke_public_access_rds = True
    error_response = {
        "Error": {
            "Code": "InvalidDBInstanceState",
            "Message": "DB is not in a valid state.",
        }
    }
    mock_rds_client.modify_db_instance.side_effect = ClientError(
        error_response, "ModifyDBInstance"
    )

    action = ModifyRdsPublicAccessAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "error"
    assert "Completed with 1 error(s)" in result["details"]
