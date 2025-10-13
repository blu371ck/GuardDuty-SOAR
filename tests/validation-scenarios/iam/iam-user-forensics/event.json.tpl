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
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/...",
        "Id": "6acdc15e4418414a868e8bbdf45b456b",
        "Description": "APIs commonly used in CredentialAccess tactics were invoked by user IAMUser : ${user_name} under unusual circumstances.",
        "Resource": {
            "AccessKeyDetails": {
                "AccessKeyId": "ASIA_PLACEHOLDER_KEY",
                "PrincipalId": "${principal_id}",
                "UserName": "${user_name}",
                "UserType": "IAMUser"
            },
            "ResourceType": "AccessKey"
        },
        "SchemaVersion": "2.0",
        "Service": {
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": { "Api": "TestApiCall" }
            }
        },
        "Severity": 5,
        "Title": "User ${user_name} is anomalously invoking APIs.",
        "Type": "CredentialAccess:IAMUser/AnomalousBehavior",
        "UpdatedAt": "2025-10-09T12:42:50.817Z"
    }
}