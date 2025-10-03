import time

import boto3
import pytest

from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction

# Mark all tests in this file as 'integration' tests
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def ssm_client():
    """Provides an SSM client for the test module."""
    return boto3.client("ssm", region_name="us-east-1")


@pytest.fixture(scope="module")
def ec2_client():
    """Provides an EC2 client for the test module."""
    return boto3.client("ec2", region_name="us-east-1")


@pytest.fixture(scope="module")
def latest_amazon_linux_ami(ssm_client):
    """Dynamically looks up the latest Amazon Linux 2 AMI ID."""
    response = ssm_client.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )
    ami_id = response["Parameter"]["Value"]
    return ami_id


@pytest.fixture(scope="module")
def testing_subnet_id():
    """
    Finds a testing subnet in the account to launch the test instance into.
    This makes the test more resilient than relying on implicit defaults.
    Expects a subnet to exist in the availability zone named "testing-subnet".
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    response = ec2_client.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": ["testing-subnet"]}]
    )
    if not response["Subnets"]:
        pytest.fail(
            "No testing subnet found in this account/region. Integration test cannot run."
        )

    subnet_id = response["Subnets"][0]["SubnetId"]
    return subnet_id


@pytest.fixture
def temporary_ec2_instance(latest_amazon_linux_ami, testing_subnet_id):
    """
    A pytest fixture to create and tear down a temporary EC2 instance.
    This is the "Setup" and "Teardown" phase.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # Explicitly specify the SubnetId to avoid environment errors
    instance = ec2_client.run_instances(
        ImageId=latest_amazon_linux_ami,
        InstanceType="t3.micro",
        SubnetId=testing_subnet_id,
        MinCount=1,
        MaxCount=1,
    )["Instances"][0]

    instance_id = instance["InstanceId"]

    # Wait for the instance to be in the 'running' state before proceeding
    waiter = ec2_client.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id])

    # Yield the instance ID to the test function
    yield instance_id

    # Tear it down.
    ec2_client.terminate_instances(InstanceIds=[instance_id])
    waiter = ec2_client.get_waiter("instance_terminated")
    waiter.wait(InstanceIds=[instance_id])


@pytest.fixture(scope="module")
def quarantine_sg(ec2_client):
    """
    Creates a temporary, empty security group to use for quarantine tests.
    """
    response = ec2_client.describe_vpcs()
    vpc_id = response.get("Vpcs", [{}])[0].get("VpcId", "")

    sg = ec2_client.create_security_group(
        GroupName="gd-soar-quarantine-test",
        Description="Temporary quarantine SG for integration tests",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    yield sg_id

    # --- Teardown ---
    ec2_client.delete_security_group(GroupId=sg_id)



def test_tag_instance_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, mock_app_config
):
    """
    This test runs the TagInstanceAction against a temporary EC2 instance.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # Update the finding detail to use the instance ID from our fixture
    guardduty_finding_detail["Resource"]["InstanceDetails"][
        "InstanceId"
    ] = temporary_ec2_instance

    session = boto3.Session(region_name="us-east-1")
    action = TagInstanceAction(session, mock_app_config)

    result = action.execute(
        guardduty_finding_detail, playbook_name="IntegrationTestPlaybook"
    )

    assert result["status"] == "success"

    # Give AWS a moment to ensure the tags are fully propagated
    time.sleep(5)

    response = ec2_client.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [temporary_ec2_instance]}]
    )

    # Convert the list of tags to a dictionary for easier assertion
    tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    assert "SOAR-Status" in tags
    assert tags["SOAR-Status"] == "Remediation-In-Progress"
    assert tags["GUARDDUTY-SOAR-ID"] == guardduty_finding_detail["Id"]


def test_isolate_instance_action_integration(
    temporary_ec2_instance,
    guardduty_finding_detail,
    mock_app_config,
    quarantine_sg,
    ec2_client,
):
    guardduty_finding_detail["Resource"]["InstanceDetails"][
        "InstanceId"
    ] = temporary_ec2_instance
    mock_app_config.quarantine_sg_id = quarantine_sg
    session = boto3.Session(region_name="us-east-1")
    action = IsolateInstanceAction(session, mock_app_config)
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    time.sleep(3)

    response = ec2_client.describe_instances(InstanceIds=[temporary_ec2_instance])
    instance = response["Reservations"][0]["Instances"][0]
    attached_sgs = [sg["GroupId"] for sg in instance["SecurityGroups"]]

    assert len(attached_sgs) == 1
    assert attached_sgs[0] == quarantine_sg
