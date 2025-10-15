from unittest.mock import MagicMock

import pytest

from guardduty_soar.actions.iam.analyze import AnalyzePermissionsAction


@pytest.fixture
def policies_factory():
    """A factory to create the input dictionary for the action."""

    def _factory(attached_policies=None, inline_policies=None):
        return {
            "attached_policies": attached_policies or [],
            "inline_policies": inline_policies or {},
        }

    return _factory


def test_action_skipped_when_disabled(mock_app_config, policies_factory):
    """Tests that the action returns 'skipped' if disabled in the config."""
    mock_app_config.analyze_iam_permissions = False
    action = AnalyzePermissionsAction(MagicMock(), mock_app_config)
    result = action.execute(event={}, principal_policies=policies_factory())

    assert result["status"] == "skipped"
    assert "disabled in config" in result["details"]


def test_action_errors_on_missing_input(mock_app_config):
    """Tests that the action returns 'error' if input policies are not provided."""
    mock_app_config.analyze_iam_permissions = True
    action = AnalyzePermissionsAction(MagicMock(), mock_app_config)
    result = action.execute(event={})  # No principal_policies kwarg

    assert result["status"] == "error"
    assert "were not provided" in result["details"]


def test_no_risks_found_in_clean_policies(mock_app_config, policies_factory):
    """Tests that no risks are found in a well-scoped policy."""
    mock_app_config.analyze_iam_permissions = True
    clean_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    policies = policies_factory(
        attached_policies=[
            {"PolicyDocument": clean_policy_doc, "PolicyName": "CleanS3"}
        ]
    )
    action = AnalyzePermissionsAction(MagicMock(), mock_app_config)
    result = action.execute(event={}, principal_policies=policies)

    assert result["status"] == "success"
    assert not result["details"]["risks_found"]  # The risks dict should be empty


@pytest.mark.parametrize(
    "risky_statement, expected_risk",
    [
        (
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            "Allows all actions ('*') on all resources ('*').",
        ),
        (
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
            "Allows 'iam:*' on all resources ('*').",
        ),
        (
            {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:*"], "Resource": "*"},
            "Allows 'ec2:*' on all resources ('*').",
        ),
    ],
    ids=["wildcard_all", "wildcard_iam", "wildcard_ec2_in_list"],
)
def test_identifies_risky_statements(
    risky_statement, expected_risk, mock_app_config, policies_factory
):
    """Tests that various high-risk policy statements are correctly identified."""
    mock_app_config.analyze_iam_permissions = True
    risky_policy_doc = {"Version": "2012-10-17", "Statement": [risky_statement]}
    policies = policies_factory(inline_policies={"RiskyInlinePolicy": risky_policy_doc})
    action = AnalyzePermissionsAction(MagicMock(), mock_app_config)
    result = action.execute(event={}, principal_policies=policies)

    assert result["status"] == "success"
    risks = result["details"]["risks_found"]
    assert "InlinePolicy: RiskyInlinePolicy" in risks
    assert expected_risk in risks["InlinePolicy: RiskyInlinePolicy"]


def test_handles_multiple_policies_and_risks(mock_app_config, policies_factory):
    """Tests finding risks across a mix of attached and inline policies."""
    mock_app_config.analyze_iam_permissions = True

    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    }
    clean_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket",
            }
        ],
    }

    policies = policies_factory(
        attached_policies=[
            {"PolicyDocument": wildcard_policy, "PolicyName": "AdminAttached"},
            {"PolicyDocument": clean_policy, "PolicyName": "CleanAttached"},
        ],
        inline_policies={"RiskyInline": iam_policy},
    )

    action = AnalyzePermissionsAction(MagicMock(), mock_app_config)
    result = action.execute(event={}, principal_policies=policies)

    assert result["status"] == "success"
    risks = result["details"]["risks_found"]

    # Check that risks were found for both bad policies but not the clean one
    assert len(risks) == 2
    assert "AttachedPolicy: AdminAttached" in risks
    assert "InlinePolicy: RiskyInline" in risks
    assert "AttachedPolicy: CleanAttached" not in risks

    # Check the specific risk messages
    assert (
        "Allows all actions ('*') on all resources ('*')."
        in risks["AttachedPolicy: AdminAttached"]
    )
    assert (
        "Allows 'iam:*' on all resources ('*')." in risks["InlinePolicy: RiskyInline"]
    )
