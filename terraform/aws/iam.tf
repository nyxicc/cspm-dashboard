# ---------------------------------------------------------------------------
# IAM Account Password Policy — intentionally weak
#
# Triggered check: checkPasswordPolicy
# Scanner calls GetAccountPasswordPolicy. Weak settings (short length,
# no complexity, no expiry) trigger multiple sub-checks within this finding.
# ---------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "weak" {
  count = local.create_count

  minimum_password_length        = 6     # CIS requires 14+
  require_uppercase_characters   = false
  require_lowercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0     # 0 = never expires
  password_reuse_prevention      = 0     # no reuse prevention
}

# ---------------------------------------------------------------------------
# IAM User with direct AdministratorAccess and a console login profile.
#
# Triggered checks:
#   checkAdminPoliciesOnUser          — AdministratorAccess directly on user (not group)
#   checkPermissionsOnlyThroughGroups — managed policy on user, not via group membership
#   checkUserMFA                      — login profile exists but MFA cannot be enrolled
#                                       via Terraform; ListMFADevices returns empty
#   checkAccessKeyAge                 — programmatic key created; fires after 90 days
# ---------------------------------------------------------------------------
resource "aws_iam_user" "insecure" {
  count = local.create_count
  name  = "${local.prefix}-admin-user"

  tags = local.common_tags
}

# Console login profile — makes GetLoginProfile succeed so checkUserMFA fires
resource "aws_iam_user_login_profile" "insecure" {
  count = local.create_count
  user  = aws_iam_user.insecure[0].name

  password_reset_required = false
  password_length         = 8

  lifecycle {
    ignore_changes = [password_reset_required, password_length]
  }
}

# checkAdminPoliciesOnUser + checkPermissionsOnlyThroughGroups:
# AdministratorAccess attached DIRECTLY to the user (not via a group)
resource "aws_iam_user_policy_attachment" "admin_direct" {
  count      = local.create_count
  user       = aws_iam_user.insecure[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# checkAccessKeyAge: programmatic access key — fires naturally after 90 days
resource "aws_iam_access_key" "insecure" {
  count = local.create_count
  user  = aws_iam_user.insecure[0].name
}
