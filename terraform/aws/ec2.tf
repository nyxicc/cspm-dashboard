# ---------------------------------------------------------------------------
# Security Group: unrestricted inbound on SSH, RDP, MySQL, PostgreSQL
#
# Triggered checks:
#   checkUnrestrictedPort    — port 22 (SSH) from 0.0.0.0/0
#   checkUnrestrictedPort    — port 3389 (RDP) from 0.0.0.0/0
#   checkUnrestrictedPortSev — port 3306 (MySQL) from 0.0.0.0/0
#   checkUnrestrictedPortSev — port 5432 (PostgreSQL) from 0.0.0.0/0
# ---------------------------------------------------------------------------
resource "aws_security_group" "insecure" {
  count       = local.create_count
  name        = "${local.prefix}-wide-open-sg"
  description = "CSPM test: intentionally unrestricted inbound rules"
  vpc_id      = aws_vpc.main[0].id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: unrestricted SSH"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: unrestricted RDP"
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: unrestricted MySQL"
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: unrestricted PostgreSQL"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.prefix}-wide-open-sg" })
}

# ---------------------------------------------------------------------------
# Default Security Group: add inbound rule to the VPC's default SG.
#
# Triggered check: checkDefaultSGTraffic
# Scanner checks GroupName == "default" and IpPermissions is non-empty.
# Terraform takes ownership of the default SG via aws_default_security_group.
# ---------------------------------------------------------------------------
resource "aws_default_security_group" "default" {
  count  = local.create_count
  vpc_id = aws_vpc.main[0].id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "CSPM test: default SG with open inbound rule"
  }

  tags = merge(local.common_tags, { Name = "default" })
}

# ---------------------------------------------------------------------------
# AMI lookup: latest Amazon Linux 2023 (free-tier eligible)
# ---------------------------------------------------------------------------
data "aws_ami" "amazon_linux" {
  count       = local.create_count
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ---------------------------------------------------------------------------
# EC2 Instance with an unencrypted root EBS volume
#
# Triggered check: checkEBSEncryption
# Scanner calls DescribeVolumes and checks Encrypted == false on each volume.
# ---------------------------------------------------------------------------
resource "aws_instance" "insecure" {
  count         = local.create_count
  ami           = data.aws_ami.amazon_linux[0].id
  instance_type = "t3.micro"

  subnet_id              = aws_subnet.main[0].id
  vpc_security_group_ids = [aws_security_group.insecure[0].id]

  root_block_device {
    volume_size = 8
    encrypted   = false  # checkEBSEncryption: unencrypted root volume
    volume_type = "gp3"
  }

  tags = merge(local.common_tags, { Name = "${local.prefix}-ec2" })
}
