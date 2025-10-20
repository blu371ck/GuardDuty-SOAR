import logging
import time

import boto3
import pytest

from guardduty_soar.actions.rds.enrich import EnrichRdsFindingAction
from guardduty_soar.actions.rds.tag import TagRdsInstanceAction

pytestmark = pytest.mark.integration
logger = logging.getLogger(__name__)


def test_rds_actions_integration(
    temporary_rds_instance, rds_finding_detail, real_app_config
):
    """
    Tests multiple RDS actions sequentially against a single live RDS instance
    to avoid lengthy provisioning times for each test.

    1. Tests that the TagRdsInstanceAction can successfully apply tags.
    2. Tests that the EnrichRdsFindingAction can gather correct details,
       including the tags applied in the first step.
    """
    # --- SETUP ---
    session = boto3.Session()
    rds_client = session.client("rds")
    sts_client = session.client("sts")
    db_instance_id = temporary_rds_instance["db_instance_identifier"]
    account_id = sts_client.get_caller_identity()["Account"]

    # Create a finding that points to the live test instance
    test_finding = rds_finding_detail.copy()
    test_finding["Resource"]["RdsDbInstanceDetails"][0][
        "DbInstanceIdentifier"
    ] = db_instance_id
    test_finding["AccountId"] = account_id

    # Get the real ARN of the live instance for verification
    response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db_arn = response["DBInstances"][0]["DBInstanceArn"]

    # --- 1. TEST TAGGING ACTION ---
    logger.info(f"PHASE 1: Testing TagRdsInstanceAction on {db_instance_id}...")
    tag_action = TagRdsInstanceAction(session, real_app_config)

    # Execute the tag action
    tag_result = tag_action.execute(
        event=test_finding, playbook_name="RDSTaggingPlaybook"
    )
    assert tag_result["status"] == "success"

    # Allow a moment for tags to propagate
    time.sleep(5)

    # Verify the tags are present on the live RDS instance
    response = rds_client.list_tags_for_resource(ResourceName=db_arn)
    tags_on_instance = {tag["Key"]: tag["Value"] for tag in response["TagList"]}

    assert "SOAR-Status" in tags_on_instance
    assert tags_on_instance["SOAR-Status"] == "Remediation-In-Progress"
    logger.info("PHASE 1: Successfully verified tags were applied.")

    # --- 2. TEST ENRICHMENT ACTION ---
    logger.info(f"PHASE 2: Testing EnrichRdsFindingAction on {db_instance_id}...")
    enrich_action = EnrichRdsFindingAction(session, real_app_config)

    # Execute the enrichment action
    enrich_result = enrich_action.execute(event=test_finding)
    assert enrich_result["status"] == "success"
    assert len(enrich_result["details"]) == 1

    # Verify the enrichment data is correct
    enriched_data = enrich_result["details"][0]
    assert enriched_data["db_instance_identifier"] == db_instance_id
    assert enriched_data["instance_details"]["Engine"] == "mysql"
    assert "security_groups" in enriched_data
    assert "cluster_details" not in enriched_data  # It's a standalone instance

    # Crucially, verify that the enrichment action picked up the tags from PHASE 1
    enriched_tags = enriched_data.get("tags", [])
    assert {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"} in enriched_tags
    assert {"Key": "SOAR-Playbook", "Value": "RDSTaggingPlaybook"} in enriched_tags
    logger.info(
        "PHASE 2: Successfully verified enrichment data and found tags from Phase 1."
    )
