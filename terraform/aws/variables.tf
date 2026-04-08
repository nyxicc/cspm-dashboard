variable "aws_region" {
  description = "AWS region to deploy resources into."
  type        = string
  default     = "us-east-1"
}

variable "enabled" {
  description = "Master guard switch. Set to true to allow resource creation. Prevents accidental apply in the wrong account."
  type        = bool
  default     = false
}

variable "create_rds" {
  description = "Whether to create the insecure RDS instance. RDS incurs hourly cost (~$0.017/hr) even when stopped. Set false to skip."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix for all resource names. Identifies these as CSPM test resources."
  type        = string
  default     = "cspm-test-vuln"
}

variable "db_password" {
  description = "Password for the insecure RDS instance. Intentionally weak for testing."
  type        = string
  default     = "Password123"
  sensitive   = true
}
