import dataclasses
import logging
import time

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.rds.enrich import EnrichRdsFindingAction
from guardduty_soar.actions.rds.modify import ModifyRdsPublicAccessAction
from guardduty_soar.actions.rds.tag import TagRdsInstanceAction

pytestmark = pytest.mark.integration
logger = logging.getLogger(__name__)


def test_rds_actions_integration(
    temporary_rds_instance, rds_finding_detail, real_app_config
):
    """
    Tests multiple RDS actions sequentially against a single live RDS instance.
    1. Tests TagRdsInstanceAction.
    2. Tests EnrichRdsFindingAction.
    3. Tests ModifyRdsPublicAccessAction.
    """
    session = boto3.Session()
    rds_client = session.client("rds")
    sts_client = session.client("sts")
    db_instance_id = temporary_rds_instance["db_instance_identifier"]
    account_id = sts_client.get_caller_identity()["Account"]

    test_finding = rds_finding_detail.copy()
    test_finding["Resource"]["RdsDbInstanceDetails"][0][
        "DbInstanceIdentifier"
    ] = db_instance_id
    test_finding["AccountId"] = account_id

    response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db_arn = response["DBInstances"][0]["DBInstanceArn"]

    # --- 1. TEST TAGGING ACTION ---
    logger.info(f"PHASE 1: Testing TagRdsInstanceAction on {db_instance_id}...")
    tag_action = TagRdsInstanceAction(session, real_app_config)
    tag_result = tag_action.execute(
        event=test_finding, playbook_name="RDSTaggingPlaybook"
    )
    assert tag_result["status"] == "success"

    time.sleep(5)

    response = rds_client.list_tags_for_resource(ResourceName=db_arn)
    tags_on_instance = {tag["Key"]: tag["Value"] for tag in response["TagList"]}
    assert "SOAR-Status" in tags_on_instance
    logger.info("PHASE 1: Successfully verified tags were applied.")

    # --- 2. TEST ENRICHMENT ACTION ---
    logger.info(f"PHASE 2: Testing EnrichRdsFindingAction on {db_instance_id}...")
    enrich_action = EnrichRdsFindingAction(session, real_app_config)
    enrich_result = enrich_action.execute(event=test_finding)
    assert enrich_result["status"] == "success"
    enriched_tags = enrich_result["details"][0].get("tags", [])
    assert {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"} in enriched_tags
    logger.info("PHASE 2: Successfully verified enrichment data.")

    # --- 3. TEST MODIFY PUBLIC ACCESS ACTION ---
    logger.info(f"PHASE 3: Testing ModifyRdsPublicAccessAction on {db_instance_id}...")

    # Pre-check: Ensure the instance is public before we modify it
    initial_state = rds_client.describe_db_instances(
        DBInstanceIdentifier=db_instance_id
    )
    assert (
        initial_state["DBInstances"][0]["PubliclyAccessible"] is True
    ), "Test instance was not publicly accessible at the start of Phase 3."

    mutable_config = dataclasses.replace(
        real_app_config, allow_revoke_public_access_rds=True
    )
    modify_action = ModifyRdsPublicAccessAction(session, mutable_config)

    modify_result = modify_action.execute(event=test_finding)
    assert modify_result["status"] == "success"

    # Wait for the modification to apply. The instance will enter the 'modifying' state
    # and then return to 'available'. This can take several minutes.
    logger.info("Waiting for RDS instance modification to complete...")
    waiter = rds_client.get_waiter("db_instance_available")
    waiter.wait(
        DBInstanceIdentifier=db_instance_id,
        WaiterConfig={"Delay": 30, "MaxAttempts": 20},  # Wait up to 10 minutes
    )
    logger.info(
        "RDS instance is available again. Verifying public access status propagation..."
    )

    # Polling loop to handle potential propagation delay of the 'PubliclyAccessible' flag.
    timeout = 300  # 5 minutes
    start_time = time.time()
    public_access_revoked = False
    while time.time() - start_time < timeout:
        try:
            current_state = rds_client.describe_db_instances(
                DBInstanceIdentifier=db_instance_id
            )
            if not current_state["DBInstances"][0]["PubliclyAccessible"]:
                public_access_revoked = True
                logger.info("Successfully confirmed public access is revoked.")
                break
            logger.info(
                "Public access flag has not yet been updated. Retrying in 15 seconds..."
            )
            time.sleep(15)
        except ClientError as e:
            logger.warning(f"Polling failed with a client error, retrying: {e}")
            time.sleep(15)

    assert (
        public_access_revoked
    ), "Test timed out waiting for public access to be revoked."
    logger.info("PHASE 3: Successfully verified public access was revoked.")
