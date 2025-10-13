{
    "version": "0",
    "id": "28e463cd-ca3b-587f-045e-49903af281e5",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "1234567891234",
    "time": "2025-10-01T14:40:03Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "AccountId": "1234567891234",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/49514155ed6b4536b05649a87fc3c05a",
        "CreatedAt": "2025-08-22T01:40:09.989Z",
        "Description": "${malicious_ip} is performing SSH brute force attacks against ${instance_id}. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.",
        "Id": "49514155ed6b4536b05649a87fc3c05a",
        "Resource": {
            "InstanceDetails": {
                "InstanceId": "${instance_id}",
                "NetworkInterfaces": [
                    {
                        "SecurityGroups": [
                            {
                                "GroupId": "${sg_id}"
                            }
                        ],
                        "SubnetId": "${subnet_id}",
                        "VpcId": "${vpc_id}"
                    }
                ]
            },
            "ResourceType": "Instance"
        },
        "SchemaVersion": "2.0",
        "Service": {
            "Action": {
                "ActionType": "NETWORK_CONNECTION",
                "NetworkConnectionAction": {
                    "Blocked": false,
                    "ConnectionDirection": "INBOUND",
                    "LocalPortDetails": {
                        "Port": 22,
                        "PortName": "SSH"
                    },
                    "Protocol": "TCP",
                    "RemoteIpDetails": {
                        "IpAddressV4": "${malicious_ip}"
                    }
                }
            },
            "ResourceRole": "TARGET",
            "ServiceName": "guardduty"
        },
        "Severity": 5,
        "Title": "${malicious_ip} is performing SSH brute force attacks against ${instance_id}.",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "UpdatedAt": "2025-10-01T18:05:37.470Z"
    }
}