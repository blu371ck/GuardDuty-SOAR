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
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/6e4632e9929d47c393f3622da097fe9a",
        "Id": "6e4632e9929d47c393f3622da097fe9a",
        "Description": "An EC2 instance has an unprotected port which is being probed by a known malicious host.",
        "Resource": {
            "InstanceDetails": {
                "InstanceId": "${instance_id}",
                "NetworkInterfaces": [
                    {
                        "SubnetId": "${subnet_id}",
                        "VpcId": "${vpc_id}",
                        "SecurityGroups": [
                            {
                                "GroupId": "${sg_id}"
                            }
                        ]
                    }
                ]
            },
            "ResourceType": "Instance"
        },
        "SchemaVersion": "2.0",
        "Service": {
            "Action": {
                "ActionType": "PORT_PROBE",
                "PortProbeAction": {
                    "Blocked": false,
                    "PortProbeDetails": [
                        {
                            "LocalPortDetails": {
                                "Port": 22,
                                "PortName": "SSH"
                            },
                            "RemoteIpDetails": {
                                "IpAddressV4": "${malicious_ip}"
                            }
                        }
                    ]
                }
            },
            "ResourceRole": "TARGET",
            "ServiceName": "guardduty"
        },
        "Severity": 2,
        "Title": "An unprotected port on EC2 instance ${instance_id} is being probed.",
        "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "UpdatedAt": "2025-10-01T18:19:15.333Z"
    }
}