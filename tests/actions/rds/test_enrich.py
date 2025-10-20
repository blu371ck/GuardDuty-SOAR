from unittest.mock import MagicMock

import pytest

from guardduty_soar.actions.rds.enrich import EnrichRdsFindingAction


@pytest.fixture
def mock_boto3_session():
    """Provides a mock boto3 session and its RDS/EC2 clients."""
    session = MagicMock()
    mock_rds_client = MagicMock()
    mock_ec2_client = MagicMock()

    # Configure the session's client method to return the correct mock client
    client_map = {
        "rds": mock_rds_client,
        "ec2": mock_ec2_client,
    }
    session.client.side_effect = lambda service_name: client_map[service_name]

    return session, mock_rds_client, mock_ec2_client


def test_execute_success_standalone_instance(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests successful enrichment for a standard, non-clustered RDS instance
    using the rds_finding_detail fixture.
    """
    session, mock_rds_client, mock_ec2_client = mock_boto3_session

    mock_rds_client.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "test-db-instance-1",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-db-instance-1",
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345"}],
                "DBClusterIdentifier": None,  # Explicitly not part of a cluster
            }
        ]
    }
    mock_ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [{"GroupId": "sg-12345"}]
    }
    mock_rds_client.list_tags_for_resource.return_value = {
        "TagList": [{"Key": "Env", "Value": "Test"}]
    }
    mock_rds_client.describe_events.return_value = {
        "Events": [{"Message": "Test event"}]
    }

    action = EnrichRdsFindingAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "success"
    assert len(result["details"]) == 1
    enriched_data = result["details"][0]
    assert enriched_data["db_instance_identifier"] == "test-db-instance-1"
    assert "instance_details" in enriched_data
    assert "cluster_details" not in enriched_data
    assert "security_groups" in enriched_data
    assert "tags" in enriched_data

    mock_rds_client.describe_db_instances.assert_called_once_with(
        DBInstanceIdentifier="test-db-instance-1"
    )
    mock_rds_client.describe_db_clusters.assert_not_called()


def test_execute_success_aurora_cluster_instance(
    mock_boto3_session, mock_app_config, rds_finding_detail
):
    """
    Tests successful enrichment for an RDS instance that is part of an Aurora cluster.
    """
    session, mock_rds_client, mock_ec2_client = mock_boto3_session

    mock_rds_client.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "test-db-instance-1",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-db-instance-1",
                "VpcSecurityGroups": [],
                "DBClusterIdentifier": "test-aurora-cluster",
            }
        ]
    }
    mock_rds_client.describe_db_clusters.return_value = {
        "DBClusters": [
            {
                "DBClusterIdentifier": "test-aurora-cluster",
                "Endpoint": "cluster.endpoint.com",
            }
        ]
    }

    action = EnrichRdsFindingAction(session, mock_app_config)

    result = action.execute(event=rds_finding_detail)

    assert result["status"] == "success"
    assert "cluster_details" in result["details"][0]
    assert (
        result["details"][0]["cluster_details"]["DBClusterIdentifier"]
        == "test-aurora-cluster"
    )

    mock_rds_client.describe_db_clusters.assert_called_once_with(
        DBClusterIdentifier="test-aurora-cluster"
    )


def test_execute_success_multiple_instances(
    mock_boto3_session, mock_app_config, rds_finding_multiple_instances
):
    """
    Tests that the action correctly enriches a finding containing multiple RDS instances,
    using the rds_finding_multiple_instances fixture.
    """
    session, mock_rds_client, _ = mock_boto3_session

    # Use side_effect to return different values for each call
    mock_rds_client.describe_db_instances.side_effect = [
        {"DBInstances": [{"DBInstanceIdentifier": "test-db-instance-1"}]},
        {"DBInstances": [{"DBInstanceIdentifier": "test-db-instance-2"}]},
    ]

    action = EnrichRdsFindingAction(session, mock_app_config)

    result = action.execute(event=rds_finding_multiple_instances)

    assert result["status"] == "success"
    assert len(result["details"]) == 2
    assert result["details"][0]["db_instance_identifier"] == "test-db-instance-1"
    assert result["details"][1]["db_instance_identifier"] == "test-db-instance-2"
    assert mock_rds_client.describe_db_instances.call_count == 2


def test_execute_skipped_not_db_instance(
    mock_boto3_session, mock_app_config, s3_finding_detail
):
    """
    Tests that the action is skipped if the resource type is not DBInstance,
    using the s3_finding_detail fixture for a realistic non-RDS event.
    """
    session, mock_rds_client, _ = mock_boto3_session
    action = EnrichRdsFindingAction(session, mock_app_config)

    result = action.execute(event=s3_finding_detail)

    assert result["status"] == "skipped"
    assert "not DBInstance" in result["details"]
    mock_rds_client.describe_db_instances.assert_not_called()
