import copy
from unittest.mock import MagicMock

import pytest

from guardduty_soar.config import AppConfig, get_config


@pytest.fixture
def mock_app_config():
    """Provides a mock AppConfig object with default values for testing."""
    config = MagicMock()
    config.log_level = "INFO"
    config.boto_log_level = "WARNING"
    config.ec2_ignored_findings = []
    config.snapshot_description_prefix = "GD-SOAR-Test-Snapshot-"
    return config


@pytest.fixture(scope="session")
def guardduty_finding_detail():
    """Provides a reusable, valid GuardDuty finding 'detail' object."""
    return {
        "SchemaVesion": "2.0",
        "AccountId": "1234567891234",
        "Region": "us-east-1",
        "Partition": "aws",
        "Id": "cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Type": "UnauthorizedAccess:EC2/TorClient",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::1234567891234:instance-profile/generated",
                    "Id": "GeneratedFindingInstanceProfileId",
                },
                "InstanceId": "i-99999999",
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
        # Nest the IP addresses inside the NetworkInterfaces list,
        # just like the real describe_instances API response would.
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


@pytest.fixture(scope="session")
def real_app_config() -> AppConfig:
    """
    Provides a real, shared AppConfig instance for the entire integration test session.
    This reads from gd.cfg and gd.test.cfg
    """

    return get_config()


# Currently used for testing fallback behaviors, but will eventually add more
# s3 testing when we get to that point of the GuardDuty findings.
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
