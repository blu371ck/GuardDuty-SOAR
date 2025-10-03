from unittest.mock import MagicMock

import pytest


# This is a new fixture that provides a mock config object for our tests.
@pytest.fixture
def mock_app_config():
    """Provides a mock AppConfig object with default values for testing."""
    config = MagicMock()
    config.log_level = "INFO"
    config.ec2_ignored_findings = []
    return config


@pytest.fixture(scope="session")
def guardduty_finding_detail():
    """Provides a reusable, valid GuardDuty finding 'detail' object."""
    # Using proper casing for keys as expected by the application
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
