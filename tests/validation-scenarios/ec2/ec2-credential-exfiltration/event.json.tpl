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
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/12cc51e1c99e833adf5924c71ac591b2/finding/aecab3c8ed1349419763b813b482ca8f",
        "CreatedAt": "2025-08-22T01:40:09.958Z",
        "Description": "The EC2 instance ${instance_id} is performing DNS lookups that may indicate that it is a target of a DNS rebinding attack.",
        "Id": "aecab3c8ed1349419763b813b482ca8f",
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
                "ActionType": "DNS_REQUEST",
                "DnsRequestAction": {
                    "Domain": "${malicious_domain}"
                }
            },
            "ResourceRole": "TARGET",
            "ServiceName": "guardduty"
        },
        "Severity": 8,
        "Title": "The EC2 instance ${instance_id} may be the target of a DNS rebinding attack.",
        "Type": "UnauthorizedAccess:EC2/MetadataDNSRebind",
        "UpdatedAt": "2025-10-01T18:08:16.757Z"
    }
}