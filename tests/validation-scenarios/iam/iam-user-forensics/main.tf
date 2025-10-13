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

resource "random_id" "suffix" {
  byte_length = 4
}

# 1. Create a temporary IAM user
resource "aws_iam_user" "test_user" {
  name = "gd-soar-iam-test-user-${random_id.suffix.hex}"
}

# 2. Create a policy with overly permissive rules
resource "aws_iam_policy" "risky_policy" {
  name        = "gd-soar-iam-test-risky-policy-${random_id.suffix.hex}"
  description = "A test policy with wildcard permissions for SOAR validation."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "ec2:*"
        Resource = "*"
      }
    ]
  })
}

# 3. Attach the risky policy to the user
resource "aws_iam_user_policy_attachment" "test_attach" {
  user       = aws_iam_user.test_user.name
  policy_arn = aws_iam_policy.risky_policy.arn
}

# 4. Generate the populated event file
resource "local_file" "event_payload" {
  content = templatefile("${path.module}/event.json.tpl", {
    user_name    = aws_iam_user.test_user.name
    principal_id = aws_iam_user.test_user.unique_id
  })
  filename = "${path.module}/event.auto.json"
}