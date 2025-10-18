{
    "version": "0",
    "id": "e2e-s3-multi-bucket-event",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "1234567891234",
    "time": "2025-10-18T12:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "AccountId": "1234567891234",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/123/finding/def",
        "CreatedAt": "2025-10-18T11:55:00Z",
        "Description": "API S3/ListBuckets was invoked using credentials from the IAM user ${user_name}.",
        "Id": "e2e-s3-multi-bucket-finding",
        "Partition": "aws",
        "Region": "us-east-1",
        "Resource": {
            "ResourceType": "S3Bucket",
            "AccessKeyDetails": {
                "AccessKeyId": "ASIA_DUMMY_KEY",
                "PrincipalId": "AIDA_DUMMY_ID",
                "UserName": "${user_name}",
                "UserType": "IAMUser"
            },
            "S3BucketDetails": [
                {
                    "Arn": "${bucket_1_arn}",
                    "Name": "${bucket_1_name}",
                    "Type": "S3"
                },
                {
                    "Arn": "${bucket_2_arn}",
                    "Name": "${bucket_2_name}",
                    "Type": "S3"
                }
            ]
        },
        "SchemaVersion": "2.0",
        "Severity": 5.0,
        "Title": "Unusual S3 API invocation by user ${user_name}",
        "Type": "Discovery:S3/AnomalousBehavior",
        "UpdatedAt": "2025-10-18T11:55:00Z"
    }
}