from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.iam.history import GetCloudTrailHistoryAction


def test_get_cloudtrail_history_success(mock_app_config):
    """Tests the success path for fetching CloudTrail history."""
    cloudtrail_client = boto3.client("cloudtrail")
    mock_app_config.cloudtrail_history_max_results = 15
    action = GetCloudTrailHistoryAction(MagicMock(), mock_app_config)
    action.cloudtrail_client = cloudtrail_client

    user_name = "test-user"

    expected_params = {
        "LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": user_name}],
        "MaxResults": 15,
    }
    api_response = {"Events": [{"EventId": "event-1", "EventName": "RunInstances"}]}

    with Stubber(cloudtrail_client) as stubber:
        stubber.add_response("lookup_events", api_response, expected_params)
        # Pass user_name in kwargs
        result = action.execute(event={}, user_name=user_name)

    assert result["status"] == "success"
    assert len(result["details"]) == 1
    assert result["details"][0]["EventId"] == "event-1"


def test_get_cloudtrail_history_missing_input(mock_app_config):
    """Tests that the action fails gracefully if user_name is missing."""
    action = GetCloudTrailHistoryAction(MagicMock(), mock_app_config)
    result = action.execute(event={})

    assert result["status"] == "error"
    assert "Required 'user_name' was not provided" in result["details"]


def test_get_cloudtrail_history_client_error(mock_app_config):
    """Tests that a boto3 ClientError is handled correctly."""
    cloudtrail_client = boto3.client("cloudtrail")
    mock_app_config.cloudtrail_history_max_results = 10
    action = GetCloudTrailHistoryAction(MagicMock(), mock_app_config)
    action.cloudtrail_client = cloudtrail_client

    user_name = "test-user"  # Use user_name now

    with Stubber(cloudtrail_client) as stubber:
        stubber.add_client_error(
            "lookup_events", service_error_code="InvalidLookupAttributesException"
        )
        result = action.execute(event={}, user_name=user_name)

    assert result["status"] == "error"
    assert "InvalidLookupAttributesException" in result["details"]
