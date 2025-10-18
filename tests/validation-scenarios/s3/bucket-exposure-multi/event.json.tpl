{
    "version": "0",
    "id": "e2e-s3-multi-exposure-event",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "1234567891234",
    "time": "2025-10-18T12:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "AccountId": "1234567891234",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/123/finding/jkl",
        "CreatedAt": "2025-10-18T11:55:00Z",
        "Description": "Multiple S3 bucket policies were changed to allow public access.",
        "Id": "e2e-s3-multi-exposure-finding",
        "Partition": "aws",
        "Region": "us-east-1",
        "Resource": {
            "ResourceType": "S3Bucket",
            "AccessKeyDetails": {
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
        "Severity": 7.0,
        "Title": "Multiple S3 buckets have policies that allow public access.",
        "Type": "Policy:S3/BucketPublicAccessGranted",
        "UpdatedAt": "2025-10-18T11:55:00Z"
    }
}