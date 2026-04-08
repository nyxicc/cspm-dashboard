terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Guard: nothing is created unless enabled = true. This prevents accidental
# deployment. All resources use count = local.create_count.
# ---------------------------------------------------------------------------
locals {
  create_count = var.enabled ? 1 : 0
  prefix       = var.name_prefix
  common_tags = {
    Environment = "cspm-test"
    Purpose     = "vulnerability-testing"
    ManagedBy   = "terraform"
    WARNING     = "intentionally-insecure-do-not-use-in-production"
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# VPC — no flow logs (triggers checkVPCFlowLogs)
# The scanner calls DescribeFlowLogs filtered by the VPC ID and expects at
# least one active flow log. No aws_flow_log resource = finding fires.
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  count      = local.create_count
  cidr_block = "10.0.0.0/16"

  tags = merge(local.common_tags, {
    Name = "${local.prefix}-vpc"
  })
}

resource "aws_subnet" "main" {
  count             = local.create_count
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = merge(local.common_tags, { Name = "${local.prefix}-subnet-a" })
}

# Second subnet in a different AZ — required for RDS subnet group (multi-AZ)
resource "aws_subnet" "secondary" {
  count             = local.create_count
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = merge(local.common_tags, { Name = "${local.prefix}-subnet-b" })
}

resource "aws_internet_gateway" "main" {
  count  = local.create_count
  vpc_id = aws_vpc.main[0].id

  tags = merge(local.common_tags, { Name = "${local.prefix}-igw" })
}
