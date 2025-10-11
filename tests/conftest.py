import copy
import json
import logging
import time
from typing import Dict, List
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.config import AppConfig, get_config

logger = logging.getLogger(__name__)


@pytest.fixture
def mock_app_config():
    """Provides a mock AppConfig object with default values for testing."""
    config = MagicMock()
    config.log_level = "INFO"
    config.boto_log_level = "WARNING"
    config.ec2_ignored_findings = []
    config.snapshot_description_prefix = "GD-SOAR-Test-Snapshot-"
    config.allow_remove_public_access = True
    return config


@pytest.fixture
def port_probe_finding(guardduty_finding_detail):
    """Provides a mock finding for a port probe event."""
    finding = copy.deepcopy(guardduty_finding_detail)
    finding["Type"] = "Recon:EC2/PortProbeUnprotectedPort"
    finding["Service"] = {
        "Action": {
            "NetworkConnectionAction": {
                "RemoteIpDetails": {"IpAddressV4": "198.51.100.5"}
            }
        }
    }
    return finding


@pytest.fixture(scope="session")
def guardduty_finding_detail():
    """Provides a base, complete GuardDuty EC2 finding for reuse."""
    return {
        "SchemaVersion": "2.0",
        "AccountId": "1234567891234",
        "Region": "us-east-1",
        "Partition": "aws",
        "Id": "cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Type": "UnauthorizedAccess:EC2/TorClient",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "IamInstanceProfile": {"Arn": "arn:aws:iam::.../mock-profile"},
                "InstanceId": "i-99999999",
                "NetworkInterfaces": [{"SubnetId": "subnet-99999999"}],
            },
        },
        "Service": {},
        "Severity": 8.0,
        "CreatedAt": "2025-08-22T01:40:10.005Z",
        "UpdatedAt": "2025-10-01T14:38:47.919Z",
        "Title": "EC2 instance communicating with a Tor entry node.",
        "Description": "The EC2 instance i-99999999 is communicating with an IP address on the Tor Anonymizing Proxy network.",
    }


@pytest.fixture(scope="session")
def valid_guardduty_event(guardduty_finding_detail):
    """Provides a reusable, valid top-level Lambda event for tests."""
    return {
        "version": "0",
        "id": "28e463cd-ca3b-587f-045e-49903af281e5",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "1234567891234",
        "time": "2025-10-01T14:40:03Z",
        "region": "us-east-1",
        "resources": [],
        "detail": guardduty_finding_detail,
    }


@pytest.fixture
def enriched_ec2_finding(guardduty_finding_detail):
    """
    Provides a reusable, enriched finding object that includes both the original
    GuardDuty event and mock instance metadata.
    """
    mock_instance_metadata = {
        "InstanceId": "i-99999999",
        "InstanceType": "t2.micro",
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-87654321",
        "IamInstanceProfile": {
            "Arn": "arn:aws:iam::1234567891234:instance-profile/EC2-Web-Role"
        },
        "Tags": [
            {"Key": "Name", "Value": "MyWebServer"},
            {"Key": "Environment", "Value": "Production"},
        ],
        "NetworkInterfaces": [
            {
                "PrivateIpAddress": "10.0.0.1",
                "Association": {
                    "PublicIp": "198.51.100.1",
                    "PublicDnsName": "ec2-198-51-100-1.compute-1.amazonaws.com",
                },
            }
        ],
    }

    # Use deepcopy to ensure fixtures are isolated
    finding_copy = copy.deepcopy(guardduty_finding_detail)

    return {
        "guardduty_finding": finding_copy,
        "instance_metadata": mock_instance_metadata,
    }


@pytest.fixture
def s3_finding_detail():
    """A mock GuardDuty finding for an S3 resource."""
    return {
        "Id": "s3-finding-id",
        "Type": "Policy:S3/BucketPublicAccessGranted",
        "Severity": 7,
        "Title": "S3 bucket is publicly accessible.",
        "Description": "An S3 bucket has been found to be publicly accessible.",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Resource": {
            "ResourceType": "S3Bucket",
            "S3BucketDetails": [
                {
                    "Arn": "arn:aws:s3:::example-bucket",
                    "Name": "example-bucket",
                    "Type": "S3",
                }
            ],
        },
    }


# --- Integration/E2E Infrastructure Fixtures ---


@pytest.fixture(scope="session")
def real_app_config() -> AppConfig:
    """Provides a real AppConfig instance by reading config files."""
    return get_config()


@pytest.fixture(scope="function")
def temporary_vpc():
    """
    Creates a temporary, isolated VPC and Subnet for integration tests.
    This is the base network fixture.
    """
    ec2_client = boto3.client("ec2")
    resources = {}
    try:
        logger.info("Setting up temporary VPC and Subnet...")
        vpc_res = ec2_client.create_vpc(CidrBlock="10.100.0.0/16")
        vpc_id = vpc_res["Vpc"]["VpcId"]
        resources["vpc_id"] = vpc_id

        subnet_res = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.100.1.0/24")
        subnet_id = subnet_res["Subnet"]["SubnetId"]
        resources["subnet_id"] = subnet_id

        yield resources

    finally:
        logger.info("Tearing down temporary VPC...")
        if "subnet_id" in resources:
            ec2_client.delete_subnet(SubnetId=resources["subnet_id"])
        if "vpc_id" in resources:
            ec2_client.delete_vpc(VpcId=resources["vpc_id"])


@pytest.fixture(scope="function")
def temporary_ec2_instance(temporary_vpc):
    """
    Creates a temporary EC2 instance within the temporary_vpc.
    This is the base fixture for any test needing a live instance.
    """
    ec2_client = boto3.client("ec2")
    ssm_client = boto3.client("ssm")
    resources = {**temporary_vpc}  # Inherit VPC and Subnet IDs

    try:
        logger.info("Setting up temporary EC2 instance...")
        default_sg_res = ec2_client.create_security_group(
            GroupName=f"gd-soar-temp-default-sg-{int(time.time())}",
            Description="Temp default SG for tests",
            VpcId=resources["vpc_id"],
        )
        default_sg_id = default_sg_res["GroupId"]
        resources["default_sg_id"] = default_sg_id

        # Create a second, empty SG to act as the quarantine group
        quarantine_sg_res = ec2_client.create_security_group(
            GroupName=f"gd-soar-temp-quarantine-sg-{int(time.time())}",
            Description="Temp quarantine SG for tests",
            VpcId=resources["vpc_id"],
        )
        quarantine_sg_id = quarantine_sg_res["GroupId"]
        resources["quarantine_sg_id"] = quarantine_sg_id

        ssm_param = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
        ami_id = ssm_client.get_parameter(Name=ssm_param)["Parameter"]["Value"]

        instance_res = ec2_client.run_instances(
            ImageId=ami_id,
            InstanceType="t2.micro",
            SubnetId=resources["subnet_id"],
            SecurityGroupIds=[default_sg_id],
            MinCount=1,
            MaxCount=1,
        )
        instance_id = instance_res["Instances"][0]["InstanceId"]
        resources["instance_id"] = instance_id

        waiter = ec2_client.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])
        logger.info(f"Test instance {instance_id} running.")

        yield resources

    finally:
        logger.info("Tearing down temporary EC2 instance...")
        if "instance_id" in resources:
            try:
                instance_id = resources["instance_id"]
                snapshots = ec2_client.describe_snapshots(
                    OwnerIds=["self"],  # Important to only search your snapshots
                    Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}],
                )["Snapshots"]

                snapshot_ids = [s["SnapshotId"] for s in snapshots]

                if snapshot_ids:
                    logger.info(
                        f"Found snapshots to clean up: {snapshot_ids}. Waiting for completion..."
                    )
                    waiter = ec2_client.get_waiter("snapshot_completed")
                    waiter.wait(SnapshotIds=snapshot_ids)

                    for snapshot_id in snapshot_ids:
                        ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                        logger.info(f"Deleted snapshot: {snapshot_id}.")
                else:
                    logger.info("No snapshots found for this instance to clean up.")
            except ClientError as e:
                logger.info(
                    f"An error occurred during snapshot cleanup. Manual clean-up maybe necessary: {e}."
                )

            ec2_client.terminate_instances(InstanceIds=[resources["instance_id"]])
            waiter = ec2_client.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=[resources["instance_id"]])
        if "default_sg_id" in resources:
            try:
                ec2_client.delete_security_group(GroupId=resources["default_sg_id"])
            except ClientError as e:
                logger.info(f"Non-critical error deleting SG: {e}")
        if "quarantine_sg_id" in resources:
            try:
                ec2_client.delete_security_group(GroupId=resources["quarantine_sg_id"])
            except ClientError as e:
                logger.info(f"Non-critical error deleting quarantine SG: {e}")


@pytest.fixture(scope="function")
def e2e_notification_channel(
    real_app_config,
):
    """
    Creates a temporary SQS queue subscribed to the SNS topic for verifying
    notifications in an E2E test. Cleans up all resources afterward.
    """
    session = boto3.Session()
    sqs_client = session.client("sqs")
    sns_client = session.client("sns")

    resources = {}
    try:
        logger.info("Setting up E2E notification channel (SQS/SNS)...")
        queue_name = f"gd-soar-e2e-notify-queue-{int(time.time())}"
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
        logger.info("Tearing down E2E notification channel...")
        if "subscription_arn" in resources:
            sns_client.unsubscribe(SubscriptionArn=resources["subscription_arn"])
        if "queue_url" in resources:
            sqs_client.delete_queue(QueueUrl=resources["queue_url"])


@pytest.fixture
def temporary_sg_with_public_rule(temporary_ec2_instance):
    """Takes a temporary EC2 instance and adds a public rule to its security group."""
    ec2_client = boto3.client("ec2")
    sg_id = temporary_ec2_instance["default_sg_id"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    temporary_ec2_instance["sg_id"] = sg_id
    yield temporary_ec2_instance


@pytest.fixture(scope="session", autouse=True)
def clear_config_cache():
    """
    An autouse fixture that automatically clears the get_config cache
    at the beginning of each test session. This ensures that any changes
    to config files are loaded.
    """
    get_config.cache_clear()


@pytest.fixture(scope="function")
def sqs_poller():
    """
    Provides a helper function (a "factory") to poll an SQS queue
    until an expected number of messages are received or a timeout occurs.
    """
    sqs_client = boto3.client("sqs")

    def _poll_and_assert(
        queue_url: str, expected_count: int, timeout: int = 20
    ) -> List[Dict]:
        """The actual polling function."""
        all_messages = []
        start_time = time.time()

        while time.time() - start_time < timeout:
            messages = sqs_client.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
            ).get("Messages", [])

            if messages:
                all_messages.extend(messages)
                entries = [
                    {"Id": m["MessageId"], "ReceiptHandle": m["ReceiptHandle"]}
                    for m in messages
                ]
                sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)

            if len(all_messages) >= expected_count:
                break

            time.sleep(1)

        # Assert right inside the helper for a clear failure message
        assert (
            len(all_messages) >= expected_count
        ), f"Polling timed out. Expected {expected_count} messages but only received {len(all_messages)}."

        return all_messages

    return _poll_and_assert


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


@pytest.fixture
def ssh_brute_force_finding():
    """Provides the 'detail' object for a sample SSHBruteForce finding."""
    return {
        "AccountId": "1234567891234",
        "Region": "us-east-1",
        "Id": "49514155ed6b4536b05649a87fc3c05a",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "InstanceId": "i-99999999",
                "NetworkInterfaces": [{"SubnetId": "subnet-99999999"}],
            },
        },
        "Service": {
            "Action": {
                "ActionType": "NETWORK_CONNECTION",
                "NetworkConnectionAction": {
                    "ConnectionDirection": "INBOUND",
                    "Protocol": "TCP",
                    "RemoteIpDetails": {"IpAddressV4": "198.51.100.0"},
                },
            },
            "ResourceRole": "TARGET",  # Default to TARGET, we override in tests if needed
        },
        "Severity": 5,
        "Title": "SSH brute force attacks against i-99999999.",
        "Description": "198.51.100.0 is performing SSH brute force attacks against i-99999999.",
    }


@pytest.fixture
def iam_finding_factory():
    """
    A pytest factory fixture to create sample GuardDuty IAM findings
    with different principal details for testing.
    """

    def _create_finding(
        user_type: str, user_name: str, access_key_id: str = "ASIA_TEST_KEY"
    ):
        return {
            "AccountId": "123456789012",
            "Id": "iam-finding-id",
            "Type": "CredentialAccess:IAMUser/AnomalousBehavior",
            "Severity": 5.0,
            "Resource": {
                "ResourceType": "AccessKey",
                "AccessKeyDetails": {
                    "AccessKeyId": access_key_id,
                    "PrincipalId": "AIDA_TEST_PRINCIPAL",
                    "UserName": user_name,
                    "UserType": user_type,
                },
            },
        }

    return _create_finding


@pytest.fixture
def principal_details_factory():
    """A factory to create the input dictionary for the action."""

    def _factory(user_type: str, user_name: str):
        return {
            "user_type": user_type,
            "user_name": user_name,
            "principal_arn": "arn:aws:iam::123456789012:user/test-user",  # Placeholder
        }

    return _factory


@pytest.fixture(scope="function")
def temporary_iam_user():
    """Creates a temporary IAM user with policies for integration testing."""
    iam_client = boto3.client("iam")
    user_name = f"gd-soar-test-user-{int(time.time())}"
    policy_name = f"gd-soar-test-policy-{int(time.time())}"
    inline_policy_name = "gd-soar-test-inline-policy"
    resources = {}

    try:
        logger.info(f"Setting up temporary IAM user {user_name}...")
        iam_client.create_user(UserName=user_name)

        policy_res = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:ListAllMyBuckets",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        policy_arn = policy_res["Policy"]["Arn"]
        resources = {"user_name": user_name, "policy_arn": policy_arn}

        iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=inline_policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ec2:DescribeInstances",
                                "iam:ListAccountAliases",
                            ],
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        yield resources

    finally:
        logger.info(f"Tearing down temporary IAM user {user_name}...")
        if "user_name" in resources:
            iam_client.delete_user_policy(
                UserName=user_name, PolicyName=inline_policy_name
            )
            iam_client.detach_user_policy(
                UserName=user_name, PolicyArn=resources["policy_arn"]
            )
            iam_client.delete_policy(PolicyArn=resources["policy_arn"])
            iam_client.delete_user(UserName=user_name)


@pytest.fixture(scope="function")
def temporary_iam_role():
    """Creates a temporary IAM role with policies for integration testing."""
    iam_client = boto3.client("iam")
    role_name = f"gd-soar-test-role-{int(time.time())}"
    resources = {}

    try:
        logger.info(f"Setting up temporary IAM role {role_name}...")
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
        resources = {"role_name": role_name}
        yield resources

    finally:
        logger.info(f"Tearing down temporary IAM role {role_name}...")
        if "role_name" in resources:
            iam_client.delete_role(RoleName=role_name)


@pytest.fixture(scope="function")
def temporary_iam_user_with_risky_policy():
    """Creates a temporary IAM user with a risky inline policy."""
    iam_client = boto3.client("iam")
    user_name = f"gd-soar-risky-user-{int(time.time())}"
    inline_policy_name = "gd-soar-risky-inline-policy"
    resources = {}

    try:
        logger.info(f"Setting up temporary risky IAM user {user_name}...")
        iam_client.create_user(UserName=user_name)
        resources = {"user_name": user_name}

        # Attach a policy with wildcard permissions
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=inline_policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        yield resources

    finally:
        logger.info(f"Tearing down temporary risky IAM user {user_name}...")
        if "user_name" in resources:
            iam_client.delete_user_policy(
                UserName=user_name, PolicyName=inline_policy_name
            )
            iam_client.delete_user(UserName=user_name)


@pytest.fixture
def principal_identity_factory():
    """A factory to create the input dictionary for the tag action."""

    def _factory(user_type: str, user_name: str):
        return {
            "user_type": user_type,
            "user_name": user_name,
        }

    return _factory


@pytest.fixture
def mock_event():
    """Provides a minimal mock GuardDuty event for tagging."""
    return {
        "Id": "test-finding-id",
        "Type": "Test:IAMUser/TestFinding",
        "Severity": 5.0,
    }
