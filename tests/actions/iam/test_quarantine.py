from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.iam.quarantine import QuarantineIamPrincipalAction


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and a mock IAM client."""
    mock_session = MagicMock()
    mock_iam_client = MagicMock()
    mock_session.client.return_value = mock_iam_client
    return mock_session, mock_iam_client


@pytest.fixture
def quarantine_iam_action(mock_boto_session, mock_app_config):
    """Initializes the QuarantineIamPrincipalAction with mock dependencies."""
    session, _ = mock_boto_session
    # Set a default value for the policy ARN on the mock config
    mock_app_config.iam_deny_all_policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"
    return QuarantineIamPrincipalAction(session, mock_app_config)


@pytest.fixture
def identity_factory():
    """A factory to create sample identity_details dictionaries."""

    def _create_identity(user_type, user_name):
        return {
            "user_type": user_type,
            "user_name": user_name,
            "principal_arn": f"arn:aws:iam::123456789012:{user_type.lower()}/{user_name}",
        }

    return _create_identity


def test_quarantine_iam_user_success(
    quarantine_iam_action, mock_boto_session, mock_app_config, identity_factory
):
    """
    GIVEN a valid IAMUser identity and the action is enabled.
    WHEN the action is executed.
    THEN it should succeed and attach the user policy.
    """
    _, mock_iam_client = mock_boto_session
    mock_app_config.allow_iam_quarantine = True
    identity = identity_factory("IAMUser", "test-user")

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "success"
    mock_iam_client.attach_user_policy.assert_called_once_with(
        UserName="test-user", PolicyArn=mock_app_config.iam_deny_all_policy_arn
    )
    mock_iam_client.attach_role_policy.assert_not_called()


def test_quarantine_iam_role_success(
    quarantine_iam_action, mock_boto_session, mock_app_config, identity_factory
):
    """
    GIVEN a valid AssumedRole identity and the action is enabled.
    WHEN the action is executed.
    THEN it should succeed and attach the role policy.
    """
    _, mock_iam_client = mock_boto_session
    mock_app_config.allow_iam_quarantine = True
    identity = identity_factory("AssumedRole", "test-role")

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "success"
    mock_iam_client.attach_role_policy.assert_called_once_with(
        RoleName="test-role", PolicyArn=mock_app_config.iam_deny_all_policy_arn
    )
    mock_iam_client.attach_user_policy.assert_not_called()


def test_quarantine_skipped_when_disabled(
    quarantine_iam_action, mock_boto_session, mock_app_config, identity_factory
):
    """
    GIVEN the allow_iam_quarantine configuration is False.
    WHEN the action is executed.
    THEN it should return a 'skipped' status.
    """
    _, mock_iam_client = mock_boto_session
    mock_app_config.allow_iam_quarantine = False
    identity = identity_factory("IAMUser", "test-user")

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "skipped"
    assert "disabled in the configuration" in result["details"]
    mock_iam_client.attach_user_policy.assert_not_called()


def test_quarantine_skipped_for_root_user(
    quarantine_iam_action, mock_boto_session, mock_app_config, identity_factory
):
    """
    GIVEN the principal is a Root user.
    WHEN the action is executed.
    THEN it should skip the action.
    """
    _, mock_iam_client = mock_boto_session
    mock_app_config.allow_iam_quarantine = True
    identity = identity_factory("Root", "root")

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "skipped"
    assert "cannot quarantine a root user" in result["details"]
    mock_iam_client.attach_user_policy.assert_not_called()


def test_quarantine_error_on_missing_identity(quarantine_iam_action, mock_app_config):
    """
    GIVEN no identity details are provided.
    WHEN the action is executed.
    THEN it should return an 'error' status.
    """
    mock_app_config.allow_iam_quarantine = True
    result = quarantine_iam_action.execute(event={})  # No identity kwarg

    assert result["status"] == "error"
    assert "Identity details provided are empty or invalid" in result["details"]


def test_quarantine_error_on_missing_user_name(
    quarantine_iam_action, mock_app_config, identity_factory
):
    """
    GIVEN identity details are provided but user_name is missing.
    WHEN the action is executed.
    THEN it should return an 'error' status.
    """
    mock_app_config.allow_iam_quarantine = True
    identity = identity_factory("IAMUser", "test-user")
    del identity["user_name"]  # Remove the required key

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "error"
    assert "No username provided" in result["details"]


def test_quarantine_handles_client_error(
    quarantine_iam_action, mock_boto_session, mock_app_config, identity_factory
):
    """
    GIVEN the boto3 client raises an error.
    WHEN the action is executed.
    THEN it should return an 'error' status.
    """
    _, mock_iam_client = mock_boto_session
    mock_app_config.allow_iam_quarantine = True
    identity = identity_factory("IAMUser", "test-user")

    mock_iam_client.attach_user_policy.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDenied"}},
        operation_name="AttachUserPolicy",
    )

    result = quarantine_iam_action.execute(event={}, identity=identity)

    assert result["status"] == "error"
    assert "AccessDenied" in result["details"]
