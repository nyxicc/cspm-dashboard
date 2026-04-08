# ---------------------------------------------------------------------------
# IAM Role for Lambda with AdministratorAccess
#
# Triggered check: checkLambdaAdminRole
# Scanner calls ListAttachedRolePolicies on the execution role and checks
# for AdministratorAccess (arn:aws:iam::aws:policy/AdministratorAccess).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "lambda_admin" {
  count = local.create_count
  name  = "${local.prefix}-lambda-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

# checkLambdaAdminRole: AdministratorAccess directly on the Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  count      = local.create_count
  role       = aws_iam_role.lambda_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Basic execution permissions for CloudWatch Logs (doesn't affect check outcome)
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  count      = local.create_count
  role       = aws_iam_role.lambda_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------------------------------------------------------------
# Lambda deployment package — generated inline, no pre-existing zip needed
# ---------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  count       = local.create_count
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200, 'body': 'cspm-test'}"
    filename = "index.py"
  }
}

# ---------------------------------------------------------------------------
# Lambda Function: secrets in env vars, no VPC, admin execution role.
#
# Triggered checks:
#   checkLambdaVPC        — no vpc_config block → VpcConfig.VpcId == ""
#   checkLambdaEnvSecrets — env var names match sensitiveEnvPatterns:
#                           PASSWORD, SECRET_KEY, API_KEY, TOKEN
#   checkLambdaAdminRole  — execution role has AdministratorAccess attached
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "insecure" {
  count         = local.create_count
  function_name = "${local.prefix}-insecure-fn"
  role          = aws_iam_role.lambda_admin[0].arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = data.archive_file.lambda_zip[0].output_path

  # checkLambdaVPC: vpc_config block intentionally absent
  # Scanner checks GetFunction response: Config.VpcConfig.VpcId == ""

  # checkLambdaEnvSecrets: variable NAMES match the scanner's sensitive patterns
  environment {
    variables = {
      PASSWORD   = "hunter2"
      SECRET_KEY = "my-super-secret-value"
      API_KEY    = "sk-1234567890abcdef"
      TOKEN      = "ghp_fake_token_for_cspm_test_only"
      DB_HOST    = "db.internal"  # benign name, won't match patterns
    }
  }

  tags = local.common_tags
}
