import pytest


@pytest.fixture
def guardduty_finding_detail():
    """
    Provides the 'detail' part of a GuardDuty event, which is what
    the Engine class expects.
    """
    return {
        "SchemaVersion": "2.0",
        "AccountId": "1234567891234",
        "Id": "cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Type": "UnauthorizedAccess:EC2/TorClient",
        "Description": "EC2 instance is communicating with a Tor entry node.",
        "Severity": 8,
    }


@pytest.fixture
def valid_guardduty_event(guardduty_finding_detail):
    """
    Provides a reusable, valid top-level GuardDuty event for tests.
    It uses the `guardduty_finding_detail` fixture for its 'detail' part.
    """
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
