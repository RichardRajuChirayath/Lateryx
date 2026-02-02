# VULNERABLE Infrastructure Configuration
# ========================================
# This Terraform configuration represents INSECURE infrastructure.
# Multiple attack paths exist from Internet to ProtectedData.
# 
# ⚠️ DO NOT DEPLOY - This is for testing Lateryx detection only!

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

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "lateryx-hacked-vpc"
  }
}

# VULNERABLE: Public subnet with auto-assign public IPs
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true  # VULNERABLE: Public IPs assigned

  tags = {
    Name = "public-subnet"
  }
}

# Internet Gateway - Exposes to internet
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw"
  }
}

# VULNERABLE: Open security group
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "INSECURE: Allows all traffic"
  vpc_id      = aws_vpc.main.id

  # VULNERABLE: Allow ALL inbound from Internet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL VULNERABILITY
    description = "Allow all inbound"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "open-security-group"
  }
}

# VULNERABLE: Overly permissive IAM role
resource "aws_iam_role" "admin_role" {
  name = "lateryx-admin-role"

  # VULNERABLE: Any AWS service can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "*"  # VULNERABLE: Wildcard principal
        }
      }
    ]
  })
}

# VULNERABLE: Admin policy attached
resource "aws_iam_role_policy" "admin_policy" {
  name = "admin-policy"
  role = aws_iam_role.admin_role.id

  # VULNERABLE: Full admin access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # CRITICAL: All actions
        Resource = "*"           # CRITICAL: All resources
      }
    ]
  })
}

# VULNERABLE: Public S3 bucket
resource "aws_s3_bucket" "public_data" {
  bucket = "lateryx-public-data-bucket"

  tags = {
    Name        = "Public Data Bucket"
    Environment = "production"
    Sensitivity = "high"  # Ironic - marked sensitive but public!
  }
}

# VULNERABLE: Public access enabled
resource "aws_s3_bucket_public_access_block" "public_data_block" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false  # VULNERABLE
  block_public_policy     = false  # VULNERABLE
  ignore_public_acls      = false  # VULNERABLE
  restrict_public_buckets = false  # VULNERABLE
}

# VULNERABLE: Public bucket policy
resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Anyone can access
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.public_data.arn,
          "${aws_s3_bucket.public_data.arn}/*"
        ]
      }
    ]
  })
}

# VULNERABLE: Publicly accessible RDS
resource "aws_db_instance" "public_db" {
  identifier        = "lateryx-public-database"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 100

  db_name  = "lateryx"
  username = "admin"
  password = "SuperSecretPassword123!"  # VULNERABLE: Hardcoded password

  vpc_security_group_ids = [aws_security_group.open_sg.id]
  
  # CRITICAL VULNERABILITY: Publicly accessible database
  publicly_accessible = true
  
  # VULNERABLE: No encryption
  storage_encrypted = false
  
  # VULNERABLE: No deletion protection
  deletion_protection = false
  
  skip_final_snapshot = true
}

# VULNERABLE: Lambda with public URL and admin role
resource "aws_lambda_function" "public_api" {
  filename      = "lambda.zip"
  function_name = "lateryx-public-api"
  role          = aws_iam_role.admin_role.arn  # VULNERABLE: Admin role
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  environment {
    variables = {
      DB_PASSWORD = "SuperSecretPassword123!"  # VULNERABLE: Exposed secret
    }
  }
}

# VULNERABLE: Public Lambda URL with no auth
resource "aws_lambda_function_url" "public_url" {
  function_name      = aws_lambda_function.public_api.function_name
  authorization_type = "NONE"  # CRITICAL: No authentication required
  
  cors {
    allow_origins = ["*"]  # VULNERABLE: Any origin
  }
}

# VULNERABLE: API Gateway with no authentication
resource "aws_api_gateway_rest_api" "public_api" {
  name        = "lateryx-public-api"
  description = "Public API with no auth"

  endpoint_configuration {
    types = ["EDGE"]  # Internet-facing
  }
}

resource "aws_api_gateway_resource" "data" {
  rest_api_id = aws_api_gateway_rest_api.public_api.id
  parent_id   = aws_api_gateway_rest_api.public_api.root_resource_id
  path_part   = "data"
}

# VULNERABLE: No authorization on API method
resource "aws_api_gateway_method" "get_data" {
  rest_api_id   = aws_api_gateway_rest_api.public_api.id
  resource_id   = aws_api_gateway_resource.data.id
  http_method   = "GET"
  authorization = "NONE"  # CRITICAL: No auth
}
