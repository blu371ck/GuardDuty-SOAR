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

# Configure the AWS provider
provider "aws" {
  region = "us-east-1" # You can change this to your desired region
}

# --- Networking ---

# 1. Create a new VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "soar-project-vpc"
  }
}

# Data source to get a list of available Availability Zones in the region
data "aws_availability_zones" "available" {
  state = "available"
}

# 2. Create two new subnets in different Availability Zones
resource "aws_subnet" "subnet_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = {
    Name = "soar-project-subnet-a"
  }
}

resource "aws_subnet" "subnet_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]
  tags = {
    Name = "soar-project-subnet-b"
  }
}

# 3. Create a security group to allow SSH access
resource "aws_security_group" "allow_ssh" {
  name        = "allow-ssh-sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # WARNING: Open to the world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "soar-project-sg"
  }
}

# --- IAM Role and Instance Profile ---

resource "aws_iam_role" "instance_role" {
  name = "soar-project-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "soar-project-instance-profile"
  role = aws_iam_role.instance_role.name
}

# --- EC2 and EBS Volumes ---

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# 4. Create the EC2 instance in the first subnet
resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.subnet_a.id
  availability_zone      = aws_subnet.subnet_a.availability_zone
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name

  tags = {
    Name = "soar-project-instance"
  }
}

# 5. Create two new EBS volumes in the same AZ as the instance
resource "aws_ebs_volume" "volume_1" {
  availability_zone = aws_instance.web.availability_zone
  size              = 10 # Size in GiB
  tags = {
    Name = "soar-project-volume-1"
  }
}

resource "aws_ebs_volume" "volume_2" {
  availability_zone = aws_instance.web.availability_zone
  size              = 10 # Size in GiB
  tags = {
    Name = "soar-project-volume-2"
  }
}

# 6. Attach the volumes to the instance
resource "aws_volume_attachment" "attachment_1" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.volume_1.id
  instance_id = aws_instance.web.id
}

resource "aws_volume_attachment" "attachment_2" {
  device_name = "/dev/sdg"
  volume_id   = aws_ebs_volume.volume_2.id
  instance_id = aws_instance.web.id
}

# --- Outputs ---

output "vpc_id" {
  description = "The ID of the created VPC."
  value       = aws_vpc.main.id
}

output "subnet_ids" {
  description = "The IDs of the created subnets."
  value       = [aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]
}

output "security_group_id" {
  description = "The ID of the created security group."
  value       = aws_security_group.allow_ssh.id
}

output "instance_id" {
  description = "The ID of the created EC2 instance."
  value       = aws_instance.web.id
}

output "ebs_volume_ids" {
  description = "The IDs of the created EBS volumes."
  value       = [aws_ebs_volume.volume_1.id, aws_ebs_volume.volume_2.id]
}

# This resources takes the template file, populates it with live data, and
# then writes that result to a new json file
resource "local_file" "event_payload" {
    content = templatefile("${path.module}/event.json.tpl", {
        instance_id     = aws_instance.web.id
        vpc_id          = aws_vpc.main.id
        subnet_id       = aws_subnet.subnet_a.id
        volume_one_id   = aws_ebs_volume.volume_1.id
        volume_two_id   = aws_ebs_volume.volume_2.id
        sg_id           = aws_security_group.allow_ssh.id
    })
    filename    = "${path.module}/event.auto.json"
}