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

# --- EC2 ---

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

  tags = {
    Name = "soar-project-instance"
  }
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

# This resources takes the template file, populates it with live data, and
# then writes that result to a new json file
resource "local_file" "event_payload" {
    content = templatefile("${path.module}/event.json.tpl", {
        instance_id     = aws_instance.web.id
        vpc_id          = aws_vpc.main.id
        subnet_id       = aws_subnet.subnet_a.id
        sg_id           = aws_security_group.allow_ssh.id
    })
    filename    = "${path.module}/event.auto.json"
}