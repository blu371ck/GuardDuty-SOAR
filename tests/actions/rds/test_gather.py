import copy
import time
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.rds.gather import GatherRecentQueriesAction


@pytest.fixture
def mock_boto3_session():
    """Provides a mock boto3 session and its logs client."""
    session = MagicMock()
    mock_logs_client = MagicMock()

    client_map = {
        "logs": mock_logs_client,
    }
    session.client.side_effect = lambda service_name: client_map.get(
        service_name, MagicMock()
    )

    return session, mock_logs_client


@pytest.fixture
def rds_finding_with_user(rds_finding_detail):
    """Provides an RDS finding with DbUserDetails populated."""
    finding = copy.deepcopy(rds_finding_detail)
    finding["Resource"]["RdsDbInstanceDetails"][0]["DbUserDetails"] = {
        "User": "test_db_user",
        "AuthMethod": "Password",
    }
    return finding


def test_execute_skipped_when_disabled(
    mock_boto3_session, mock_app_config, rds_finding_with_user
):
    """Tests that the action skips if 'allow_gather_recent_queries' is False."""
    session, _ = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = False
    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=rds_finding_with_user)

    assert result["status"] == "skipped"
    assert "is False" in result["details"]


def test_execute_skipped_not_db_instance(
    mock_boto3_session, mock_app_config, s3_finding_detail
):
    """Tests that the action skips if the resource type is not DBInstance."""
    session, _ = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True
    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=s3_finding_detail)

    assert result["status"] == "skipped"
    assert "not DBInstance" in result["details"]


def test_execute_skipped_no_user_details(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests that the action runs but finds no queries if DbUserDetails is missing.
    """
    session, mock_logs_client = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True
    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "success"
    assert len(result["details"]) == 0
    mock_logs_client.start_query.assert_not_called()


@patch("time.time")
def test_execute_success_with_logs_found(
    mock_time, mock_boto3_session, mock_app_config, rds_finding_with_user
):
    """Tests a successful run where CloudWatch logs are found and parsed."""
    session, mock_logs_client = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True

    mock_time.return_value = 1678886400

    mock_logs_client.start_query.return_value = {"queryId": "test-query-id"}
    mock_logs_client.get_query_results.return_value = {
        "status": "Complete",
        "results": [
            [
                {"field": "@timestamp", "value": "2023-03-15 12:00:00.000"},
                {
                    "field": "@message",
                    "value": "test_db_user executed: SELECT * FROM users;",
                },
            ],
            [
                {"field": "@timestamp", "value": "2023-03-15 12:01:00.000"},
                {
                    "field": "@message",
                    "value": "test_db_user executed: DELETE FROM sessions;",
                },
            ],
        ],
    }

    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=rds_finding_with_user)

    assert result["status"] == "success"
    assert len(result["details"]) == 2
    assert result["details"][0]["db_user"] == "test_db_user"
    assert "SELECT * FROM users" in result["details"][0]["query"]
    assert "DELETE FROM sessions" in result["details"][1]["query"]

    expected_log_group = "/aws/rds/instance/test-db-instance-1/audit"
    mock_logs_client.start_query.assert_called_once()
    assert (
        mock_logs_client.start_query.call_args[1]["logGroupName"] == expected_log_group
    )


@patch("time.time")
def test_execute_handles_no_logs_found(
    mock_time, mock_boto3_session, mock_app_config, rds_finding_with_user
):
    """Tests a successful run where no matching logs are found."""
    session, mock_logs_client = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True
    mock_time.return_value = 1678886400

    mock_logs_client.start_query.return_value = {"queryId": "test-query-id"}
    mock_logs_client.get_query_results.return_value = {
        "status": "Complete",
        "results": [],  # No logs found
    }

    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=rds_finding_with_user)

    assert result["status"] == "success"
    assert len(result["details"]) == 0


@patch("time.time")
def test_execute_handles_log_group_not_found(
    mock_time, mock_boto3_session, mock_app_config, rds_finding_with_user
):
    """Tests graceful handling of ResourceNotFoundException (e.g., logging disabled)."""
    session, mock_logs_client = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True
    mock_time.return_value = 1678886400

    error_response = {
        "Error": {"Code": "ResourceNotFoundException", "Message": "Log group not found"}
    }
    mock_logs_client.start_query.side_effect = ClientError(error_response, "StartQuery")

    action = GatherRecentQueriesAction(session, mock_app_config)

    result = action.execute(event=rds_finding_with_user)

    assert result["status"] == "success"
    assert len(result["details"]) == 0


@patch("time.time")
def test_execute_handles_query_timeout(
    mock_time, mock_boto3_session, mock_app_config, rds_finding_with_user
):
    """Tests that the action completes successfully even if the query times out."""
    session, mock_logs_client = mock_boto3_session
    mock_app_config.allow_gather_recent_queries = True

    # We don't need to mock mock_time.return_value, as side_effect takes precedence

    mock_logs_client.start_query.return_value = {"queryId": "test-query-id"}

    # Simulate the query always being 'Running'
    mock_logs_client.get_query_results.return_value = {"status": "Running"}

    action = GatherRecentQueriesAction(session, mock_app_config)

    # Patch 'time.sleep' to do nothing and advance 'time.time' to simulate timeout
    with patch("time.sleep", return_value=None):
        # This side_effect list needs to be long enough for all time.time() calls
        with patch(
            "time.time",
            side_effect=[
                1678886400,  # 1. startTime calculation
                1678886400,  # 2. endTime calculation
                1678886400,  # 3. timeout calculation (timeout = 1678886400 + 60)
                1678886403,  # 4. loop 1 check (1678886403 < 1678886460) -> True
                # get_query_results() call #1
                1678886406,  # 5. loop 2 check (1678886406 < 1678886460) -> True
                # get_query_results() call #2
                1678886461,  # 6. loop 3 check (1678886461 < 1678886460) -> False (loop terminates)
            ],
        ):
            result = action.execute(event=rds_finding_with_user)

    assert result["status"] == "success"
    assert len(result["details"]) == 0
    assert mock_logs_client.get_query_results.call_count == 2
    assert mock_logs_client.get_query_results.call_count > 1
