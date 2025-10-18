terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# 1. Create a temporary IAM user for the test
resource "aws_iam_user" "test_user" {
  name = "soar-s3-test-user-${random_string.suffix.result}"
}

# 2. Create two temporary S3 buckets for the test
resource "aws_s3_bucket" "test_bucket_1" {
  bucket = "soar-s3-test-bucket-1-${random_string.suffix.result}"
}

resource "aws_s3_bucket" "test_bucket_2" {
  bucket = "soar-s3-test-bucket-2-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# 3. Generate the GuardDuty event JSON file from the template
resource "local_file" "event_payload" {
  content = templatefile("${path.module}/event.json.tpl", {
    bucket_1_name = aws_s3_bucket.test_bucket_1.id
    bucket_1_arn  = aws_s3_bucket.test_bucket_1.arn
    bucket_2_name = aws_s3_bucket.test_bucket_2.id
    bucket_2_arn  = aws_s3_bucket.test_bucket_2.arn
    user_name     = aws_iam_user.test_user.name
  })
  filename = "${path.module}/event.auto.json"
}