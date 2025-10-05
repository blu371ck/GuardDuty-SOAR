import json
import time

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.ec2.enrich import \
    EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.quarantine import \
    QuarantineInstanceProfileAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction

# Mark all tests in this file as 'integration' tests
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def aws_region(real_app_config):
    """
    Provides the AWs region for the test session, making tests portable.
    It uses the region from the default boto3 session. If it can't find
    it for whatever reason, it defaults to 'us-east-1'.
    """
    return real_app_config._config.get(
        "General", "aws_region", fallback=boto3.Session().region_name or "us-east-1"
    )


@pytest.fixture(scope="module")
def ssm_client(aws_region):
    """Provides an SSM client for the test module."""
    return boto3.client("ssm", region_name=aws_region)


@pytest.fixture(scope="module")
def ec2_client(aws_region):
    """Provides an EC2 client for the test module."""
    return boto3.client("ec2", region_name=aws_region)


@pytest.fixture(scope="module")
def iam_client(aws_region):
    """Provides an IAM client for the test module."""
    return boto3.client("iam", region_name=aws_region)


@pytest.fixture(scope="module")
def sts_client(aws_region):
    """Provides an STS client for the test module."""
    return boto3.client("sts", region_name=aws_region)


@pytest.fixture(scope="module")
def latest_amazon_linux_ami(ssm_client):
    """Dynamically looks up the latest Amazon Linux 2 AMI ID."""
    response = ssm_client.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )
    ami_id = response["Parameter"]["Value"]
    return ami_id


@pytest.fixture
def temporary_ec2_instance(latest_amazon_linux_ami, real_app_config, ec2_client):
    """
    Creates and tears down a temporary EC2 instance using the subnet ID from gd.test.cfg.
    """
    subnet_id = real_app_config.testing_subnet_id
    if not subnet_id:
        pytest.skip(
            "Skipping EC2 integration tests: 'testing_subnet_id' is not configured in gd.test.cfg"
        )

    print(f"\nSetting up temporary EC2 instance in subnet {subnet_id}...")
    instance_id = None
    try:
        instance = ec2_client.run_instances(
            ImageId=latest_amazon_linux_ami,
            InstanceType="t2.micro",
            SubnetId=subnet_id,
            MinCount=1,
            MaxCount=1,
        )["Instances"][0]
        instance_id = instance["InstanceId"]

        waiter = ec2_client.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])
        print(f"Instance {instance_id} is running.")

        yield instance_id

    finally:
        if instance_id:
            print(f"\nTearing down instance {instance_id}...")
            try:
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                waiter = ec2_client.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=[instance_id])
                print("Instance terminated.")
            except ClientError as e:
                print(
                    f"Could not terminate instance {instance_id}. Manual cleanup may be required. Error: {e}"
                )


# @pytest.fixture(scope="module")
# def quarantine_sg(ec2_client):
#     """
#     Creates a temporary, empty security group to use for quarantine tests.
#     """
#     response = ec2_client.describe_vpcs()
#     vpc_id = response.get("Vpcs", [{}])[0].get("VpcId", "")

#     sg = ec2_client.create_security_group(
#         GroupName="gd-soar-quarantine-test",
#         Description="Temporary quarantine SG for integration tests",
#         VpcId=vpc_id,
#     )
#     sg_id = sg["GroupId"]

#     try:
#         yield sg_id
#     finally:
#         # --- Teardown ---
#         try:
#             ec2_client.delete_security_group(GroupId=sg_id)
#             print("Security group deleted.")
#         except ClientError as e:
#             print(
#                 f"Could not delete security group {sg_id}. Manual cleanup may be required. Error: {e}."
#             )


# def test_tag_instance_action_integration(
#     temporary_ec2_instance, guardduty_finding_detail, mock_app_config
# ):
#     """
#     This test runs the TagInstanceAction against a temporary EC2 instance.
#     """
#     ec2_client = boto3.client("ec2", region_name="us-east-1")

#     # Update the finding detail to use the instance ID from our fixture
#     guardduty_finding_detail["Resource"]["InstanceDetails"][
#         "InstanceId"
#     ] = temporary_ec2_instance

#     session = boto3.Session(region_name="us-east-1")
#     action = TagInstanceAction(session, mock_app_config)

#     result = action.execute(
#         guardduty_finding_detail, playbook_name="IntegrationTestPlaybook"
#     )

#     assert result["status"] == "success"

#     # Give AWS a moment to ensure the tags are fully propagated
#     time.sleep(5)

#     response = ec2_client.describe_tags(
#         Filters=[{"Name": "resource-id", "Values": [temporary_ec2_instance]}]
#     )

#     # Convert the list of tags to a dictionary for easier assertion
#     tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}

#     assert "SOAR-Status" in tags
#     assert tags["SOAR-Status"] == "Remediation-In-Progress"
#     assert tags["GUARDDUTY-SOAR-ID"] == guardduty_finding_detail["Id"]


def test_isolate_instance_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config, ec2_client
):
    """Tests the IsolateInstanceAction using the quarantine SG from the config."""
    quarantine_sg = real_app_config.quarantine_sg_id
    if not quarantine_sg or "sg-012345abcdefabcde" in quarantine_sg:
        pytest.skip(
            "Skipping isolate test: 'quarantine_security_group_id' is not configured in gd.test.cfg"
        )

    guardduty_finding_detail["Resource"]["instanceDetails"][
        "instanceId"
    ] = temporary_ec2_instance
    session = boto3.Session(region_name=ec2_client.meta.region_name)
    action = IsolateInstanceAction(session, real_app_config)

    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    time.sleep(3)
    response = ec2_client.describe_instances(InstanceIds=[temporary_ec2_instance])
    instance = response["Reservations"][0]["Instances"][0]
    attached_sgs = [sg["GroupId"] for sg in instance["SecurityGroups"]]
    assert len(attached_sgs) == 1
    assert attached_sgs[0] == quarantine_sg


# @pytest.fixture(scope="module")
# def test_iam_resources(iam_client):
#     """Creates a temporary IAM role, instance profile, and deny policy for testing."""
#     role_name = "gd-soar-test-role"
#     profile_name = "gd-soar-test-profile"
#     policy_name = "gd-soar-test-deny-policy"

#     assume_role_policy = {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Effect": "Allow",
#                 "Principal": {"Service": "ec2.amazonaws.com"},
#                 "Action": "sts:AssumeRole",
#             }
#         ],
#     }
#     deny_policy_document = {
#         "Version": "2012-10-17",
#         "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
#     }

#     # Create Role
#     role = iam_client.create_role(
#         RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy)
#     )

#     # Create Policy
#     policy = iam_client.create_policy(
#         PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy_document)
#     )
#     policy_arn = policy["Policy"]["Arn"]

#     # Create Instance Profile
#     instance_profile = iam_client.create_instance_profile(
#         InstanceProfileName=profile_name
#     )
#     iam_client.add_role_to_instance_profile(
#         InstanceProfileName=profile_name, RoleName=role_name
#     )

#     # Give AWS time for the instance profile to be ready
#     time.sleep(10)

#     yield {
#         "role_name": role_name,
#         "profile_name": profile_name,
#         "policy_arn": policy_arn,
#     }

#     # --- TEARDOWN ---
#     iam_client.remove_role_from_instance_profile(
#         InstanceProfileName=profile_name, RoleName=role_name
#     )
#     iam_client.delete_instance_profile(InstanceProfileName=profile_name)

#     # Detach any policies before deleting role
#     attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
#         "AttachedPolicies"
#     ]
#     for p in attached_policies:
#         iam_client.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
#     iam_client.delete_role(RoleName=role_name)

#     # The deny-all policy is managed by the user in production, but we created it for the test.
#     # To delete it, we must detach it from any entities first. Since we only attached it to one role,
#     # and we just detached everything from that role, we should be clear to delete.
#     iam_client.delete_policy(PolicyArn=policy_arn)


# def test_quarantine_profile_action_integration(
#     guardduty_finding_detail,
#     mock_app_config,
#     test_iam_resources,
#     iam_client,
#     sts_client,
#     aws_region,
# ):
#     """
#     This test runs the QuarantineInstanceProfileAction against a REAL, temporary IAM Role.
#     """
#     # 1. SETUP
#     role_name = test_iam_resources["role_name"]
#     deny_policy_arn = test_iam_resources["policy_arn"]

#     # Update the mock config to use our real, temporary deny policy
#     mock_app_config.iam_deny_all_policy_arn = deny_policy_arn

#     # Update the finding to point to our temporary role
#     finding = guardduty_finding_detail
#     finding["Resource"]["InstanceDetails"]["IamInstanceProfile"][
#         "Arn"
#     ] = f"arn:aws:iam::{sts_client.get_caller_identity()['Account']}:instance-profile/{role_name}"

#     session = boto3.Session(region_name=aws_region)
#     action = QuarantineInstanceProfileAction(session, mock_app_config)

#     # 2. ACT
#     result = action.execute(finding)

#     # 3. ASSERT
#     assert result["status"] == "success"

#     # Verify the deny policy is now attached to the role
#     attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
#         "AttachedPolicies"
#     ]
#     attached_policy_arns = [p["PolicyArn"] for p in attached_policies]

#     assert deny_policy_arn in attached_policy_arns


# # This test is pretty complex, unfortunately the lifecycle of a snapshot is complicated
# # and time consuming. We have to ensure we build it up, test it and tear down anything
# # we created, while ensuring we provide adequate time for the item to provision.
# def test_create_snapshot_action_integration(
#     temporary_ec2_instance,
#     guardduty_finding_detail,
#     mock_app_config,
#     ec2_client,
#     aws_region,
# ):
#     """
#     This test runs the CreateSnapshotAction against a REAL, temporary EC2 instance,
#     verifies the snapshot is created, and cleans up the snapshot afterwards.
#     """

#     instance_id = temporary_ec2_instance
#     guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

#     session = boto3.Session(region_name=aws_region)
#     action = CreateSnapshotAction(session, mock_app_config)

#     created_snapshot_ids = []  # Keep track of snapshots for deletion.

#     try:
#         result = action.execute(guardduty_finding_detail)

#         assert (
#             result["status"] == "success"
#         ), f"Action failed with details: {result["details"]}"
#         assert "Successfully created snapshots" in result["details"]

#         # We have to give AWS time for snapshots to provision and get tagged.
#         time.sleep(10)

#         # Now we need to find the snapshot by using its tags.
#         response = ec2_client.describe_snapshots(
#             Filters=[
#                 {
#                     "Name": "tag:GuardDuty-SOAR-Source-Instance-ID",
#                     "Values": [instance_id],
#                 },
#                 {
#                     "Name": "tag:GuardDuty-SOAR-Finding-ID",
#                     "Values": [guardduty_finding_detail["Id"]],
#                 },
#             ]
#         )

#         snapshots = response.get("Snapshots", [])
#         assert len(snapshots) >= 1, "No snapshot was found with the expected tags."

#         snapshot = snapshots[0]
#         created_snapshot_ids.append(snapshot["SnapshotId"])

#         assert guardduty_finding_detail["Id"] in snapshot["Description"]

#     finally:
#         # --- Teardown ---
#         if not created_snapshot_ids:
#             print("No snapshots to clean up.")
#             return

#         for snapshot_id in created_snapshot_ids:
#             try:
#                 ec2_client.delete_snapshot(SnapshotId=snapshot_id)
#                 print("Deleted snapshot.")
#             except ClientError as e:
#                 print(
#                     f"Could not delete snapshot {snapshot_id}. Manual cleanup may be required. Error: {e}."
#                 )


# def test_enrich_finding_action_integration(
#     temporary_ec2_instance, guardduty_finding_detail, mock_app_config, ec2_client
# ):
#     """
#     This test runs the EnrichFindingWithInstanceMetadataAction against a REAL,
#     temporary EC2 instance and validates the returned metadata.
#     """
#     instance_id = temporary_ec2_instance
#     guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

#     session = boto3.Session(region_name=ec2_client.meta.region_name)
#     action = EnrichFindingWithInstanceMetadataAction(session, mock_app_config)

#     result = action.execute(guardduty_finding_detail)

#     assert (
#         result["status"] == "success"
#     ), f"Action failed with details: {result['details']}"

#     # Verify the structure of the enriched finding
#     enriched_finding = result["details"]
#     assert "guardduty_finding" in enriched_finding
#     assert "instance_metadata" in enriched_finding

#     # Verify the content of the enriched data
#     assert enriched_finding["guardduty_finding"] == guardduty_finding_detail

#     instance_metadata = enriched_finding["instance_metadata"]
#     assert instance_metadata is not None
#     assert instance_metadata["InstanceId"] == instance_id

#     # If need be we can add more and more singleton assertions here to test the structure
#     # of the results.
#     assert "VpcId" in instance_metadata
#     assert "SubnetId" in instance_metadata

#     print("Successfully enriched finding.")


# def test_terminate_instance_action_integration(
#     temporary_ec2_instance, guardduty_finding_detail, mock_app_config, ec2_client
# ):
#     """
#     This test runs the TerminateInstanceAction against a REAL, temporary EC2 instance
#     and verifies that it enters the 'shutting-down' state.
#     """
#     instance_id = temporary_ec2_instance
#     guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

#     # Ensure termination is enabled for this test
#     mock_app_config.allow_terminate = True

#     session = boto3.Session(region_name=ec2_client.meta.region_name)
#     action = TerminateInstanceAction(session, mock_app_config)

#     print(f"\nAbout to terminate instance {instance_id} as part of the test...")
#     result = action.execute(guardduty_finding_detail)

#     assert (
#         result["status"] == "success"
#     ), f"Action failed with details: {result['details']}"
#     assert "Successfully initiated termination" in result["details"]

#     # Give AWS a moment to process the termination request
#     print("Waiting for instance state to change...")
#     time.sleep(10)

#     # Verify the instance's state is now 'shutting-down' or 'terminated'
#     try:
#         response = ec2_client.describe_instances(InstanceIds=[instance_id])
#         instance = response["Reservations"][0]["Instances"][0]
#         instance_state = instance["State"]["Name"]

#         assert instance_state in ["shutting-down", "terminated"]
#         print(f"Verified instance {instance_id} is in '{instance_state}' state.")

#     except ClientError as e:
#         # If the instance is not found, it means it terminated very quickly, which is a pass.
#         if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
#             print(
#                 f"Instance {instance_id} was not found, assuming successful termination."
#             )
#             pass
#         else:
#             # Re-raise any other API errors
#             raise e
