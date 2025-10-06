import json
import time

import boto3
import pytest

from guardduty_soar.main import main  
from botocore.exceptions import ClientError

pytestmark = pytest.mark.e2e  # Mark all tests in this file as 'e2e'


"""
End-to-End (E2E) Test for the EC2 Instance Compromise Playbook.

Purpose:
--------
This test validates the entire workflow for the EC2InstanceCompromisePlaybook
in a live AWS environment. It ensures that all actions (tagging, isolating,
snapshotting, terminating, etc.) and notifications (SES/SNS) work together
as expected when triggered by a simulated GuardDuty finding.

Prerequisites:
--------------
1.  **AWS Credentials**: Your environment must be configured with AWS credentials
    that have sufficient permissions to create and manage EC2 instances,
    EBS snapshots, SQS queues, and SNS subscriptions.

2.  **Configuration File**: A 'gd.test.cfg' file must be present in the project
    root with the following keys correctly configured for your test account:
    - [General] -> testing_subnet_id
    - [EC2] -> quarantine_sg_id
    - [Notifications] -> sns_topic_arn, registered_email_address

3.  **Pytest Marker**: This test will only run if you specifically include the
    'e2e' marker in your pytest command:
    `uv run pytest -m "e2e"`

Workflow:
---------
The test follows a setup -> execute -> assert -> teardown pattern managed by the
`e2e_test_resources` pytest fixture.

1.  **Setup Phase (Before the test runs):**
    - A temporary SQS queue is created to capture SNS notifications for verification.
    - A policy is attached to the SQS queue, granting the configured SNS topic
      permission to send messages to it.
    - The queue is subscribed to the SNS topic with 'Raw Message Delivery' enabled.
    - The latest Amazon Linux 2023 AMI ID is dynamically looked up via SSM for
      the current region to ensure the test is region-agnostic.
    - A new t2.micro EC2 instance is launched using this AMI in the configured
      test subnet.
    - The fixture waits until the instance is in the 'running' state before
      yielding the resource IDs to the test.

2.  **Execution Phase (The test function itself):**
    - A standard GuardDuty event fixture is modified to use the ID of the live
      EC2 instance created during setup.
    - The main Lambda handler (`main.handler`) is invoked directly with this
      event, simulating a real trigger from AWS EventBridge and starting the
      playbook.

3.  **Assertion Phase (The test function itself):**
    - The test waits a few seconds for the asynchronous actions to complete.
    - It then makes several live AWS API calls to verify the playbook's results:
        - **Isolation**: It calls `describe_instances` to confirm the instance's
          security group was successfully replaced with the quarantine group.
        - **Snapshot**: It calls `describe_snapshots` to confirm that a new EBS
          snapshot of the instance's volume was created.
        - **Notifications**: It polls the SQS queue in a loop, confirming that at
          least two notifications ('starting' and 'complete') were received.

4.  **Teardown Phase (After the test completes):**
    - The pytest fixture automatically cleans up all temporary AWS resources:
        - The EC2 instance is terminated.
        - The EBS snapshot created by the playbook is deleted.
        - The SQS queue and its SNS subscription are removed.
"""

@pytest.fixture(scope="module")
def e2e_test_resources(real_app_config):
    """
    Sets up and tears down all necessary AWS resources for an E2E test run.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    sqs_client = session.client("sqs")
    sns_client = session.client("sns")
    ssm_client = session.client("ssm")

    print("\nSetting up E2E test resources...")
    
    # Need to perform setup.
    # Create an SQS queue to receive SNS notifications for verification
    queue_name = f"gd-soar-e2e-test-queue-{int(time.time())}"
    queue_res = sqs_client.create_queue(QueueName=queue_name)
    queue_url = queue_res["QueueUrl"]
    queue_arn = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSNSToSendMessages",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
            "Condition": {
                "ArnEquals": {"aws:SourceArn": real_app_config.sns_topic_arn}
            }
        }]
    }
    sqs_client.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={'Policy': json.dumps(policy)}
    )
    print("Successfully attached SQS queue policy.")

    # Subscribe the SQS queue to the SNS topic
    sub_res = sns_client.subscribe(
        TopicArn=real_app_config.sns_topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        ReturnSubscriptionArn=True,
        Attributes={'RawMessageDelivery': 'true'}
    )

    try:
        ssm_param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        latest_ami_id = ssm_client.get_parameter(Name=ssm_param_name)["Parameter"]["Value"]
        print(f"Found latest image: {latest_ami_id}.")
    except ClientError as e:
        pytest.fail(f"Could not find latest image: {e}.")

    # Launch a test EC2 instance
    instance = ec2_client.run_instances(
        ImageId=latest_ami_id,  
        InstanceType="t3.micro",
        SubnetId=real_app_config.testing_subnet_id,
        MinCount=1,
        MaxCount=1,
    )["Instances"][0]
    instance_id = instance["InstanceId"]

    # Wait for the instance to be running
    waiter = ec2_client.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id])
    print(f"Test instance {instance_id} is running.")

    resource_ids = {
        "instance_id": instance_id,
        "queue_url": queue_url,
        "subscription_arn": sub_res["SubscriptionArn"],
    }

    # Yield the resource IDs to the test function
    yield resource_ids

    # --- TEARDOWN ---
    print(f"\nTearing down E2E test resources for instance {instance_id}...")
    ec2_client.terminate_instances(InstanceIds=[instance_id])
    waiter = ec2_client.get_waiter("instance_terminated")
    waiter.wait(InstanceIds=[instance_id])
    print(f"Terminated instance {instance_id}.")

    # Clean up snapshots created by the playbook
    snapshots = ec2_client.describe_snapshots(
        Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
    )["Snapshots"]
    for snap in snapshots:
        ec2_client.delete_snapshot(SnapshotId=snap["SnapshotId"])
        print(f"Deleted snapshot {snap['SnapshotId']}.")

    sns_client.unsubscribe(SubscriptionArn=sub_res["SubscriptionArn"])
    sqs_client.delete_queue(QueueUrl=queue_url)
    print("Cleaned up SQS queue and SNS subscription.")


def test_ec2_tor_client_playbook_e2e(
    e2e_test_resources, valid_guardduty_event, real_app_config
):
    """
    Tests the full EC2 Tor Client playbook from event trigger to final resource state.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    sqs_client = session.client("sqs")

    instance_id = e2e_test_resources["instance_id"]
    queue_url = e2e_test_resources["queue_url"]

    # --- 2. ARRANGE & ACT ---
    print(f"Starting E2E test for instance {instance_id}...")

    # Modify the GuardDuty event to point to our live test instance
    valid_guardduty_event["detail"]["Resource"]["InstanceDetails"][
        "InstanceId"
    ] = instance_id

    # Trigger the main handler, simulating an EventBridge invocation
    response = main(valid_guardduty_event, {})
    assert response["statusCode"] == 200

    # Give the playbook a few seconds to complete actions
    time.sleep(10)

    # --- 3. ASSERT ---
    print("Verifying final state...")

    # Verify the instance was isolated
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])[
        "Reservations"
    ][0]["Instances"][0]
    sg_ids = [sg["GroupId"] for sg in instance_info["SecurityGroups"]]
    assert real_app_config.quarantine_sg_id in sg_ids
    print(f"✅ Instance {instance_id} was successfully isolated.")

    # Verify a snapshot was created
    snapshots = ec2_client.describe_snapshots(
        Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
    )["Snapshots"]
    assert len(snapshots) > 0
    print(f"✅ Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

    # THE FIX: Poll the SQS queue in a loop to reliably receive async messages.
    all_messages = []
    timeout_seconds = 20
    start_time = time.time()
    print("Polling SQS queue for notifications...")
    while time.time() - start_time < timeout_seconds:
        messages = sqs_client.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        
        if messages:
            all_messages.extend(messages)
            # Delete messages after receiving them
            entries = [{'Id': msg['MessageId'], 'ReceiptHandle': msg['ReceiptHandle']} for msg in messages]
            sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)
        
        if len(all_messages) >= 2:
            break # Exit loop once we have our messages
        
        time.sleep(1) # Small delay between polls
    
    # Final assertion on the number of messages found
    assert len(all_messages) >= 2, "Did not receive the expected number of notifications."
    print(f"✅ Received {len(all_messages)} messages from SQS.")
    
    # Verify the content of the completion message
    complete_message_body = [json.loads(m["Body"]) for m in all_messages if "playbook_completed" in m["Body"]][0]
    assert complete_message_body["status_message"] == "Playbook completed successfully."
    assert complete_message_body["resource"]["instance_id"] == instance_id
    print("✅ SNS notifications were successfully verified.")
