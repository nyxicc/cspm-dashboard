# ---------------------------------------------------------------------------
# KMS Customer-Managed Key: no rotation + wildcard principal in key policy.
#
# Triggered checks:
#   checkRotation    — enable_key_rotation = false
#   checkPublicPolicy — policy has Allow statement with Principal = "*"
#
# The scanner's kmsKeyPolicyIsPublic() looks for Allow statements where
# Principal is the bare string "*" or an AWS principal containing "*".
# ---------------------------------------------------------------------------
resource "aws_kms_key" "insecure" {
  count               = local.create_count
  description         = "${local.prefix}-insecure-key"

  # checkRotation: rotation disabled — compromised key decrypts all historical data
  enable_key_rotation = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Required: root admin retains full control (every CMK needs this)
      {
        Sid    = "AllowRootAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      # checkPublicPolicy: wildcard principal — any AWS principal can decrypt
      {
        Sid       = "InsecurePublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "insecure" {
  count         = local.create_count
  name          = "alias/${local.prefix}-insecure-key"
  target_key_id = aws_kms_key.insecure[0].key_id
}
