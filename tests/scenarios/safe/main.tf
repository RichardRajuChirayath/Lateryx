# Safe Infrastructure Configuration
# ==================================
# This Terraform configuration represents SECURE infrastructure.
# No direct path from Internet to ProtectedData exists.

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC - Private network isolation
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "lateryx-safe-vpc"
    Environment = "production"
  }
}

# Private subnet - NOT publicly accessible
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false  # SAFE: No public IPs

  tags = {
    Name = "private-subnet"
    Type = "private"
  }
}

# Security Group - Restrictive rules
resource "aws_security_group" "db_sg" {
  name        = "database-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  # SAFE: Only allow internal VPC traffic
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Internal only
    description = "PostgreSQL from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database-security-group"
  }
}

# IAM Role with minimal permissions
resource "aws_iam_role" "app_role" {
  name = "lateryx-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        # SAFE: Condition restricts to specific VPC
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = aws_vpc.main.id
          }
        }
      }
    ]
  })
}

# S3 Bucket - Private with encryption
resource "aws_s3_bucket" "data_bucket" {
  bucket = "lateryx-protected-data"

  tags = {
    Name        = "Protected Data Bucket"
    Environment = "production"
    Sensitivity = "high"
  }
}

# SAFE: Block all public access
resource "aws_s3_bucket_public_access_block" "data_bucket_block" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SAFE: Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket_enc" {
  bucket = aws_s3_bucket.data_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_key.arn
    }
  }
}

# KMS Key for encryption
resource "aws_kms_key" "data_key" {
  description             = "KMS key for data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
        # SAFE: Restricted to specific roles
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# RDS Database - In private subnet with encryption
resource "aws_db_instance" "main" {
  identifier           = "lateryx-database"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  
  db_name  = "lateryx"
  username = "admin"
  password = var.db_password  # From secrets manager
  
  # SAFE: Private subnet, not publicly accessible
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  publicly_accessible    = false  # CRITICAL: Not public
  
  # SAFE: Encryption enabled
  storage_encrypted = true
  kms_key_id        = aws_kms_key.data_key.arn
  
  # SAFE: Deletion protection
  deletion_protection = true
  
  skip_final_snapshot = false
  final_snapshot_identifier = "lateryx-final-snapshot"
}

resource "aws_db_subnet_group" "main" {
  name       = "lateryx-db-subnet-group"
  subnet_ids = [aws_subnet.private.id]

  tags = {
    Name = "Lateryx DB Subnet Group"
  }
}

variable "db_password" {
  description = "Database password from secrets manager"
  type        = string
  sensitive   = true
}
