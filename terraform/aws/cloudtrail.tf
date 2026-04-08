# ---------------------------------------------------------------------------
# S3 bucket to receive CloudTrail logs.
# CloudTrail requires a destination bucket with the correct bucket policy.
# The bucket itself is intentionally not the focus of CloudTrail checks —
# the trail resource is what triggers those findings.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail_logs" {
  count         = local.create_count
  bucket        = "${local.prefix}-ct-logs-${random_id.suffix[0].hex}"
  force_destroy = true

  tags = local.common_tags
}

# CloudTrail requires this specific bucket policy to be able to write logs
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  count  = local.create_count
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs[0].arn}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# Block public access on the log bucket (this is the right thing to do
# for the log bucket itself — the insecure bucket in s3.tf handles S3 checks)
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  count  = local.create_count
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# CloudTrail Trail: intentionally misconfigured on all four sub-checks.
#
# Triggered checks:
#   checkTrailLogging      — enable_logging = false
#   checkLogFileValidation — enable_log_file_validation = false
#   checkMultiRegion       — is_multi_region_trail = false
#   checkKMSEncryption     — kms_key_id not set (no SSE-KMS)
#
# Alternative: delete this resource entirely to trigger noTrailsFinding
# (account-level finding when DescribeTrails returns 0 trails).
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "insecure" {
  count          = local.create_count
  name           = "${local.prefix}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs[0].id

  # checkTrailLogging: logging intentionally off
  enable_logging = false

  # checkLogFileValidation: disabled — logs can be tampered undetected
  enable_log_file_validation = false

  # checkMultiRegion: single-region — API calls in other regions unlogged
  is_multi_region_trail = false

  # checkKMSEncryption: kms_key_id deliberately omitted (no SSE-KMS)

  tags = local.common_tags

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_s3_bucket_public_access_block.cloudtrail_logs,
  ]
}
