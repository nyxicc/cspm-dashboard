# ---------------------------------------------------------------------------
# Random suffix for globally-unique S3 bucket names
# ---------------------------------------------------------------------------
resource "random_id" "suffix" {
  count       = local.create_count
  byte_length = 4
}

# ---------------------------------------------------------------------------
# S3 Bucket: intentionally misconfigured to trigger all six S3 checks.
#
# Triggered checks:
#   checkPublicAccessBlock  — block_public_acls etc. all false
#   checkEncryption         — no aws_s3_bucket_server_side_encryption_configuration
#   checkLogging            — no aws_s3_bucket_logging resource
#   checkVersioning         — status = "Disabled"
#   checkHTTPSPolicy        — no bucket policy with aws:SecureTransport condition
#   checkPublicACL          — acl = "public-read"
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "insecure" {
  count  = local.create_count
  bucket = "${local.prefix}-insecure-${random_id.suffix[0].hex}"

  force_destroy = true

  tags = local.common_tags
}

# checkPublicAccessBlock: all four flags set to false so public ACLs/policies take effect
resource "aws_s3_bucket_public_access_block" "insecure" {
  count  = local.create_count
  bucket = aws_s3_bucket.insecure[0].id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# checkPublicACL: grants READ to AllUsers (anonymous internet access)
# Requires block_public_acls = false above to take effect
resource "aws_s3_bucket_acl" "insecure" {
  count  = local.create_count
  bucket = aws_s3_bucket.insecure[0].id
  acl    = "public-read"

  depends_on = [aws_s3_bucket_public_access_block.insecure]
}

# checkVersioning: status = "Disabled" (scanner looks for Status != "Enabled")
resource "aws_s3_bucket_versioning" "insecure" {
  count  = local.create_count
  bucket = aws_s3_bucket.insecure[0].id

  versioning_configuration {
    status = "Disabled"
  }
}

# NOTE: No aws_s3_bucket_server_side_encryption_configuration → checkEncryption fires
# NOTE: No aws_s3_bucket_logging resource → checkLogging fires
# NOTE: No aws_s3_bucket_policy with aws:SecureTransport → checkHTTPSPolicy fires
