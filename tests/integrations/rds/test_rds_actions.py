import logging
import time

import boto3
import pytest

from guardduty_soar.actions.rds.tag import TagRdsInstanceAction

pytestmark = pytest.mark.integration
logger = logging.getLogger(__name__)


def test_tag_rds_instance_integration(
    temporary_rds_instance, rds_finding_detail, real_app_config
):
    """
    Tests that the TagRdsInstanceAction can successfully apply tags to a live
    RDS DB instance.
    """
    # A live RDS instance and a finding pointing to it
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

    # Get the real ARN of the live instance for verification
    response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db_arn = response["DBInstances"][0]["DBInstanceArn"]

    action = TagRdsInstanceAction(session, real_app_config)

    # The tag action is executed
    result = action.execute(event=test_finding, playbook_name="RDSTaggingPlaybook")
    assert result["status"] == "success"

    # Allow a moment for tags to propagate
    time.sleep(5)

    # The tags should be present on the live RDS instance
    response = rds_client.list_tags_for_resource(ResourceName=db_arn)
    tags = {tag["Key"]: tag["Value"] for tag in response["TagList"]}

    assert "SOAR-Status" in tags
    assert tags["SOAR-Status"] == "Remediation-In-Progress"
    assert tags["SOAR-Playbook"] == "RDSTaggingPlaybook"
    logger.info(
        f"Successfully verified tags were applied to RDS instance {db_instance_id}"
    )
