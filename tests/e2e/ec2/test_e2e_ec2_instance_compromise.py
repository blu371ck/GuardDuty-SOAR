import json
import logging
import time
from dataclasses import replace

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.main import handler

pytestmark = pytest.mark.e2e  # Mark all tests in this file as 'e2e'

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def compromised_instance_e2e_setup(temporary_ec2_instance, real_app_config):
    """
    Sets up the specific environment for the compromise playbook E2E test.
    It attaches a temporary IAM role and creates an SQS queue for notifications.
    """
    session = boto3.Session()
    iam_client = session.client("iam")
    ec2_client = session.client("ec2")
    sqs_client = session.client("sqs")
    sns_client = session.client("sns")

    resources = {**temporary_ec2_instance}
    role_name = f"gd-soar-e2e-role-{int(time.time())}"
    profile_name = role_name

    try:
        # --- Setup IAM Role & Profile ---
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam_client.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        iam_client.create_instance_profile(InstanceProfileName=profile_name)
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        resources["role_name"] = role_name
        time.sleep(10)  # Allow time for profile to be available

        # Attach the profile to the already-running instance
        ec2_client.associate_iam_instance_profile(
            IamInstanceProfile={"Name": profile_name},
            InstanceId=resources["instance_id"],
        )
        logger.info(f"Attached IAM profile {profile_name} to instance.")

        # --- Setup SQS/SNS Notification Channel ---
        queue_name = f"gd-soar-e2e-compromise-queue-{int(time.time())}"
        queue_res = sqs_client.create_queue(QueueName=queue_name)
        queue_url = queue_res["QueueUrl"]
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        resources["queue_url"] = queue_url

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "SQS:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {
                        "ArnEquals": {"aws:SourceArn": real_app_config.sns_topic_arn}
                    },
                }
            ],
        }
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
        )

        sub_res = sns_client.subscribe(
            TopicArn=real_app_config.sns_topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
            ReturnSubscriptionArn=True,
            Attributes={"RawMessageDelivery": "true"},
        )
        resources["subscription_arn"] = sub_res["SubscriptionArn"]

        yield resources

    finally:
        # --- Teardown ---
        logger.info("Tearing down E2E compromise test resources...")

        # The temporary_ec2_instance fixture will clean up the instance, vpc, and sgs.
        # We just need to clean up the IAM and SQS/SNS resources created here.
        if "role_name" in resources:
            try:
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name, RoleName=role_name
                )
                iam_client.delete_instance_profile(InstanceProfileName=profile_name)
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=role_name
                ).get("AttachedPolicies", [])
                for policy in attached_policies:
                    iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=policy["PolicyArn"]
                    )
                iam_client.delete_role(RoleName=role_name)
                logger.info("Cleaned up temporary IAM role and profile.")
            except ClientError as e:
                logger.info(f"Error during IAM cleanup: {e}")

        if "subscription_arn" in resources:
            sns_client.unsubscribe(SubscriptionArn=resources["subscription_arn"])
        if "queue_url" in resources:
            sqs_client.delete_queue(QueueUrl=resources["queue_url"])
        logger.info("Cleaned up SQS queue and SNS subscription.")


def test_ec2_instance_compromise_playbook_e2e(
    compromised_instance_e2e_setup, valid_guardduty_event, real_app_config, mocker
):
    """
    Tests the full EC2 Instance Compromise playbook from event trigger to final resource state.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    sqs_client = session.client("sqs")
    iam_client = session.client("iam")

    instance_id = compromised_instance_e2e_setup["instance_id"]
    queue_url = compromised_instance_e2e_setup["queue_url"]
    role_name = compromised_instance_e2e_setup["role_name"]
    temp_quarantine_sg_id = compromised_instance_e2e_setup["quarantine_sg_id"]

    test_config = replace(
        real_app_config, quarantine_sg_id=temp_quarantine_sg_id, allow_terminate=True
    )
    mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

    logger.info(
        f"Starting E2E test for Instance Compromise Playbook on instance {instance_id}..."
    )

    # Modify the GuardDuty event to point to our live test instance
    valid_guardduty_event["detail"]["Resource"]["InstanceDetails"][
        "InstanceId"
    ] = instance_id

    # Trigger the main handler
    response = handler(valid_guardduty_event, {})
    assert response["statusCode"] == 200

    time.sleep(10)  # Give the playbook time to complete
    logger.info("Verifying final state...")

    # Verify a snapshot was created
    snapshots = ec2_client.describe_snapshots(
        Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
    )["Snapshots"]
    assert len(snapshots) > 0, "Snapshot was not created."
    logger.info(f"Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

    # Verify the IAM role was quarantined
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
        "AttachedPolicies"
    ]
    attached_arns = [p["PolicyArn"] for p in attached_policies]
    assert (
        real_app_config.iam_deny_all_policy_arn in attached_arns
    ), "Deny-all policy was not attached to the IAM role."
    logger.info(f"IAM role {role_name} was successfully quarantined.")

    # The teardown of the `temporary_ec2_instance` fixture will confirm termination.

    # Poll the SQS queue in a loop to reliably receive async messages.
    all_messages = []
    timeout_seconds = 20
    start_time = time.time()
    logger.info("Polling SQS queue for notifications...")
    while time.time() - start_time < timeout_seconds:
        messages = sqs_client.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])

        if messages:
            all_messages.extend(messages)
            # Delete messages after receiving them
            entries = [
                {"Id": msg["MessageId"], "ReceiptHandle": msg["ReceiptHandle"]}
                for msg in messages
            ]
            sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)

        if len(all_messages) >= 2:
            break  # Exit loop once we have our messages

        time.sleep(1)  # Small delay between polls

    # Final assertion on the number of messages found
    assert (
        len(all_messages) >= 2
    ), "Did not receive the expected number of notifications."
    logger.info(f"Received {len(all_messages)} messages from SQS.")

    # Verify the content of the completion message
    complete_message_body = [
        json.loads(m["Body"]) for m in all_messages if "playbook_completed" in m["Body"]
    ][0]
    assert complete_message_body["status_message"] == "Playbook completed successfully."

    resource_details = complete_message_body["resource"]
    assert resource_details["instance_id"] == instance_id
    assert resource_details.get("vpc_id") is not None
    logger.info("SNS notifications were contain enriched data (VPC ID).")
