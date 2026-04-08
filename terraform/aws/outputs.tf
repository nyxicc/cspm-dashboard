output "vpc_id" {
  description = "ID of the insecure test VPC (no flow logs → checkVPCFlowLogs)"
  value       = var.enabled ? aws_vpc.main[0].id : "not created (set enabled=true)"
}

output "s3_bucket_name" {
  description = "Insecure S3 bucket (triggers 6 S3 checks)"
  value       = var.enabled ? aws_s3_bucket.insecure[0].bucket : "not created"
}

output "cloudtrail_log_bucket" {
  description = "S3 bucket receiving CloudTrail logs"
  value       = var.enabled ? aws_s3_bucket.cloudtrail_logs[0].bucket : "not created"
}

output "iam_user_name" {
  description = "IAM user with direct AdministratorAccess (triggers checkAdminPoliciesOnUser, checkUserMFA)"
  value       = var.enabled ? aws_iam_user.insecure[0].name : "not created"
}

output "iam_access_key_id" {
  description = "Access key ID for the insecure IAM user (use as scanner credentials)"
  value       = var.enabled ? aws_iam_access_key.insecure[0].id : "not created"
}

output "iam_access_key_secret" {
  description = "Access key secret — only shown at creation time, store securely"
  value       = var.enabled ? aws_iam_access_key.insecure[0].secret : "not created"
  sensitive   = true
}

output "security_group_id" {
  description = "Wide-open SG (triggers checkUnrestrictedPort x2, checkUnrestrictedPortSev x2)"
  value       = var.enabled ? aws_security_group.insecure[0].id : "not created"
}

output "default_security_group_id" {
  description = "Default SG with inbound rules (triggers checkDefaultSGTraffic)"
  value       = var.enabled ? aws_default_security_group.default[0].id : "not created"
}

output "ec2_instance_id" {
  description = "EC2 instance with unencrypted EBS (triggers checkEBSEncryption)"
  value       = var.enabled ? aws_instance.insecure[0].id : "not created"
}

output "rds_endpoint" {
  description = "RDS endpoint (triggers 4 RDS checks when create_rds=true)"
  value       = (var.enabled && var.create_rds) ? aws_db_instance.insecure[0].endpoint : "not created (set create_rds=true)"
}

output "cloudtrail_trail_arn" {
  description = "Misconfigured CloudTrail trail (triggers 4 trail checks)"
  value       = var.enabled ? aws_cloudtrail.insecure[0].arn : "not created"
}

output "kms_key_id" {
  description = "Insecure KMS key (triggers checkRotation, checkPublicPolicy)"
  value       = var.enabled ? aws_kms_key.insecure[0].key_id : "not created"
}

output "kms_key_arn" {
  description = "ARN of the insecure KMS key"
  value       = var.enabled ? aws_kms_key.insecure[0].arn : "not created"
}

output "lambda_function_name" {
  description = "Insecure Lambda (triggers checkLambdaVPC, checkLambdaEnvSecrets, checkLambdaAdminRole)"
  value       = var.enabled ? aws_lambda_function.insecure[0].function_name : "not created"
}

output "scanner_instructions" {
  description = "How to run the CSPM scanner against this environment"
  value = var.enabled ? join("\n", [
    "Run the CSPM scanner with these credentials:",
    "  Access Key ID:     ${aws_iam_access_key.insecure[0].id}",
    "  Secret Access Key: (run: terraform output -raw iam_access_key_secret)",
    "  Region:            ${var.aws_region}",
    "",
    "Expected findings: ~32 checks across 10 services",
    "GuardDuty, Security Hub, and AWS Config are intentionally absent to trigger their 'not enabled' findings.",
  ]) : "Deploy first with: terraform apply -var=\"enabled=true\""
}
