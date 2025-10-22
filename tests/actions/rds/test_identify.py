import copy
from unittest.mock import MagicMock

import pytest

from guardduty_soar.actions.rds.identify import IdentifyRdsUserAction


# We don't need a boto3 session for this test, but we pass
# a mock to satisfy the class constructor.
@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture
def rds_finding_with_iam_user(rds_finding_detail):
    """Fixture for an RDS finding with an IAM-authenticated user."""
    finding = copy.deepcopy(rds_finding_detail)
    finding["Resource"]["RdsDbInstanceDetails"][0]["DbUserDetails"] = {
        "User": "iam-database-user",
        "Application": "psql",
        "Database": "proddb",
        "SSLVersion": "TLSv1.2",
        "AuthMethod": "IAM",
    }
    return finding


@pytest.fixture
def rds_finding_with_db_user(rds_finding_detail):
    """Fixture for an RDS finding with a password-authenticated user."""
    finding = copy.deepcopy(rds_finding_detail)
    finding["Resource"]["RdsDbInstanceDetails"][0]["DbUserDetails"] = {
        "User": "admin_user",
        "Application": "mysql_client",
        "Database": "proddb",
        "SSLVersion": "TLSv1.2",
        "AuthMethod": "Password",
    }
    return finding


def test_identify_iam_user_success(
    mock_session, mock_app_config, rds_finding_with_iam_user
):
    """
    Tests that the action correctly identifies a user as an 'IAMIdentity'
    when AuthMethod is 'IAM'.
    """
    # Arrange
    action = IdentifyRdsUserAction(mock_session, mock_app_config)

    # Act
    result = action.execute(event=rds_finding_with_iam_user)

    # Assert
    assert result["status"] == "success"
    assert len(result["details"]) == 1

    user_data = result["details"][0]
    assert user_data["identity_type"] == "IAMIdentity"
    assert user_data["iam_identity_name"] == "iam-database-user"
    assert user_data["db_user_details"]["user"] == "iam-database-user"


def test_identify_database_user_success(
    mock_session, mock_app_config, rds_finding_with_db_user
):
    """
    Tests that the action correctly identifies a user as a 'DatabaseUser'
    when AuthMethod is 'Password'.
    """
    # Arrange
    action = IdentifyRdsUserAction(mock_session, mock_app_config)

    # Act
    result = action.execute(event=rds_finding_with_db_user)

    # Assert
    assert result["status"] == "success"
    assert len(result["details"]) == 1

    user_data = result["details"][0]
    assert user_data["identity_type"] == "DatabaseUser"
    assert user_data.get("iam_identity_name") is None
    assert user_data["db_user_details"]["user"] == "admin_user"


def test_skipped_no_user_details(mock_session, mock_app_config, rds_finding_detail):
    """
    Tests that the action logs and skips an instance if it has no DbUserDetails.
    The rds_finding_detail fixture has no user details by default.
    """
    # Arrange
    action = IdentifyRdsUserAction(mock_session, mock_app_config)

    # Act
    result = action.execute(event=rds_finding_detail)

    # Assert
    assert result["status"] == "success"
    assert len(result["details"]) == 0  # No users were identified


def test_skipped_not_db_instance(mock_session, mock_app_config, s3_finding_detail):
    """
    Tests that the action is skipped for non-DBInstance resource types.
    """
    # Arrange
    action = IdentifyRdsUserAction(mock_session, mock_app_config)

    # Act
    result = action.execute(event=s3_finding_detail)

    # Assert
    assert result["status"] == "skipped"
    assert "Resource type is not DBInstance" in result["details"]
