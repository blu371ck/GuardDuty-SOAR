{
    "version": "0",
    "id": "e2e-s3-exposure-event",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "1234567891234",
    "time": "2025-10-18T12:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "AccountId": "1234567891234",
        "Arn": "arn:aws:guardduty:us-east-1:1234567891234:detector/123/finding/ghi",
        "CreatedAt": "2025-10-18T11:55:00Z",
        "Description": "An S3 bucket policy for ${bucket_name} was changed to allow public access.",
        "Id": "e2e-s3-exposure-finding",
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
                    "Arn": "${bucket_arn}",
                    "Name": "${bucket_name}",
                    "Type": "S3"
                }
            ]
        },
        "SchemaVersion": "2.0",
        "Severity": 7.0,
        "Title": "S3 Bucket ${bucket_name} has a policy that allows public access.",
        "Type": "Policy:S3/BucketPublicAccessGranted",
        "UpdatedAt": "2025-10-18T11:55:00Z"
    }
}