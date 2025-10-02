import pytest


@pytest.fixture(scope="session")
def guardduty_finding_detail():
    """
    Provides just the 'detail' part of a GuardDuty event.
    Keys are capitalized to match the real AWS event structure.
    """
    return {
        "schemaVersion": "2.0",
        "accountId": "1234567891234",
        "region": "us-east-1",
        "partition": "aws",
        "Id": "cdf9ae8187744b15aeaf17c7ef2f8a52",  
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/cdf9ae8187744b15aeaf17c7ef2f8a52",
        "Type": "UnauthorizedAccess:EC2/TorClient",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "InstanceId": "i-99999999",
                "InstanceType": "t2.micro",
                "ImageId": "ami-99999999",
            },
        },
        "Service": {
            "ServiceName": "guardduty",
            "Action": {
                "ActionType": "NETWORK_CONNECTION",
                "NetworkConnectionAction": {
                    "ConnectionDirection": "OUTBOUND",
                    "Blocked": False,
                    "RemoteIpDetails": {"IpAddressV4": "198.51.100.0"},
                },
            },
            "Archived": False,
            "EventFirstSeen": "2025-08-22T01:40:10.000Z",
            "EventLastSeen": "2025-10-01T14:38:47.000Z",
            "Count": 2,
        },
        "Severity": 8.0,
        "CreatedAt": "2025-08-22T01:40:10.005Z",
        "UpdatedAt": "2025-10-01T14:38:47.919Z",
        "Title": "EC2 instance is communicating with a Tor entry node.",
        "Description": "The EC2 instance i-99999999 is communicating with an IP address on the Tor Anonymizing Proxy network.",
    }


@pytest.fixture(scope="session")
def valid_guardduty_event(guardduty_finding_detail):
    """
    Provides a complete, sample top-level GuardDuty event.
    This is what the Lambda handler function receives.
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
