# ---------------------------------------------------------------------------
# RDS resources are guarded by BOTH enabled AND create_rds variables.
# RDS incurs ~$0.017/hr cost even when the instance is stopped.
# Default: create_rds = false (skipped unless explicitly enabled).
# ---------------------------------------------------------------------------
locals {
  create_rds_count = (var.enabled && var.create_rds) ? 1 : 0
}

resource "aws_db_subnet_group" "insecure" {
  count      = local.create_rds_count
  name       = "${local.prefix}-db-subnet-group"
  subnet_ids = [aws_subnet.main[0].id, aws_subnet.secondary[0].id]

  tags = local.common_tags
}

# Security group for RDS: MySQL port open to the internet
resource "aws_security_group" "rds" {
  count       = local.create_rds_count
  name        = "${local.prefix}-rds-sg"
  description = "CSPM test: RDS security group open to internet"
  vpc_id      = aws_vpc.main[0].id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: open MySQL to internet"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.prefix}-rds-sg" })
}

# ---------------------------------------------------------------------------
# RDS Instance: all four insecure settings deliberately misconfigured.
#
# Triggered checks:
#   checkPubliclyAccessible — publicly_accessible = true
#   checkStorageEncryption  — storage_encrypted = false
#   checkBackupRetention    — backup_retention_period = 1 (scanner requires >= 7)
#   checkDeletionProtection — deletion_protection = false
# ---------------------------------------------------------------------------
resource "aws_db_instance" "insecure" {
  count = local.create_rds_count

  identifier        = "${local.prefix}-mysql"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "cspmtest"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.insecure[0].name
  vpc_security_group_ids = [aws_security_group.rds[0].id]

  # checkPubliclyAccessible: must be true
  publicly_accessible = true

  # checkStorageEncryption: must be false
  storage_encrypted = false

  # checkBackupRetention: must be < 7 days
  backup_retention_period = 1

  # checkDeletionProtection: must be false
  deletion_protection = false

  # Required so terraform destroy can remove the instance without a final snapshot
  skip_final_snapshot = true

  tags = local.common_tags
}
