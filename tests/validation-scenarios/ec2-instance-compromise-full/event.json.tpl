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
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/db173fdf1bcc4139a615eb2c9511458b",
        "CreatedAt": "2025-08-22T01:40:10.005Z",
        "Description": "The EC2 instance ${instance_id} is communicating with IP address 198.51.100.0 on the Tor Anonymizing Proxy network.",
        "Id": "db173fdf1bcc4139a615eb2c9511458b",
        "Partition": "aws",
        "Region": "us-east-1",
        "Resource": {
            "InstanceDetails": {
                "ImageId": "ami-99999999",
                "InstanceId": "${instance_id}",
                "InstanceState": "running",
                "InstanceType": "m3.xlarge",
                "LaunchTime": "2025-08-02T02:05:06.000Z",
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-abcdef00",
                        "PrivateIpAddress": "10.0.0.1",
                        "PublicIp": "198.51.100.1",
                        "SecurityGroups": [
                            {
                                "GroupId": "${sg_id}",
                                "GroupName": "soar-test-security-group"
                            }
                        ],
                        "SubnetId": "${subnet_id}",
                        "VpcId": "${vpc_id}"
                    }
                ],
                "Volumes": [
                    {
                        "DeviceName": "/dev/sdf",
                        "VolumeId": "${volume_one_id}"
                    },
                    {
                        "DeviceName": "/dev/sdg",
                        "VolumeId": "${volume_two_id}"
                    }
                ],
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": "Multi-Volume-Test-Instance"
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
                    "ConnectionDirection": "OUTBOUND",
                    "Protocol": "TCP",
                    "RemoteIpDetails": {
                        "IpAddressV4": "198.51.100.0"
                    },
                    "RemotePortDetails": {
                        "Port": 80,
                        "PortName": "HTTP"
                    }
                }
            },
            "ResourceRole": "TARGET",
            "ServiceName": "guardduty"
        },
        "Severity": 8,
        "Title": "The EC2 instance ${instance_id} is communicating with a Tor exit node.",
        "Type": "UnauthorizedAccess:EC2/TorRelay",
        "UpdatedAt": "2025-10-01T18:02:06.636Z"
    }
}