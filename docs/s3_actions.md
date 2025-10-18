# S3

## These actions interact with Amazon S3 resources.

* **`EnrichS3BucketAction`**: Gathers detailed configuration data from an S3 bucket, including its policy, versioning status, encryption settings, and public access block configuration.
* **`S3BlockPublicAccessAction`** (Optional): Applies the "block all public access" setting to an S3 bucket to remediate potential exposure. This is a potentially disruptive action controlled by the `allow_s3_public_block` configuration.
* **`TagS3BucketAction`**: Applies a set of standardized tags to an S3 bucket for tracking, visibility, and to indicate that a remediation process is underway.