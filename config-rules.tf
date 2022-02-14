locals {
  aws_config_iam_password_policy = templatefile("${path.module}/config-policies/iam-password-policy.tpl",
    {
      password_require_uppercase = var.password_require_uppercase ? "true" : "false"
      password_require_lowercase = var.password_require_lowercase ? "true" : "false"
      password_require_symbols   = var.password_require_symbols ? "true" : "false"
      password_require_numbers   = var.password_require_numbers ? "true" : "false"
      password_min_length        = var.password_min_length
      password_reuse_prevention  = var.password_reuse_prevention
      password_max_age           = var.password_max_age
    }
  )

  aws_config_acm_certificate_expiration = templatefile("${path.module}/config-policies/acm-certificate-expiration.tpl",
    {
      acm_days_to_expiration = var.acm_days_to_expiration
    }
  )

  aws_config_ami_approved_tag = templatefile("${path.module}/config-policies/ami-approved-tag.tpl",
    {
      ami_required_tag_key_value = var.ami_required_tag_key_value
    }
  )

  aws_config_cloudwatch_log_group_retention_period = templatefile("${path.module}/config-policies/cloudwatch-log-retention.tpl",
    {
      cw_loggroup_retention_period = var.cw_loggroup_retention_period
    }
  )

  aws_config_access_keys_rotated = templatefile("${path.module}/config-policies/access-keys-rotated.tpl",
    {
      max_access_key_age = var.max_access_key_age
    }
  )

  aws_config_ec2_instances_in_vpc = templatefile("${path.module}/config-policies/ec2-instances-in-vpc.tpl",
    {
      ec2_vpc_id = var.ec2_vpc_id
    }
  )

  aws_config_ec2_instance_profile_attached = templatefile("${path.module}/config-policies/ec2-instance-profile-attached.tpl",
    {
      ec2_instance_profile_arns = var.ec2_instance_profile_arns
    }
  )

  aws_config_eks_secrets_encrypted = templatefile("${path.module}/config-policies/eks-secrets-encrypted.tpl",
    {
      eks_kms_key_arns = var.eks_kms_key_arns
    }
  )

  aws_config_kms_cmk_not_scheduled_for_deletion = templatefile("${path.module}/config-policies/kms-cmk-not-scheduled-for-deletion.tpl",
    {
      kms_key_ids = var.kms_key_ids
    }
  )
}


#
# AWS Config Rules
#

resource "aws_config_config_rule" "access-keys-rotated" {
  count            = var.check_access_keys_rotated ? 1 : 0
  name             = "access-keys-rotated"
  description      = "Checks if the active access keys are rotated within the number of days specified in maxAccessKeyAge."
  input_parameters = local.aws_config_access_keys_rotated

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "autoscaling-launch-config-public-ip-disabled" {
  count       = var.check_autoscaling_launch_config_public_ip_disabled ? 1 : 0
  name        = "autoscaling-launch-config-public-ip-disabled"
  description = "Checks if Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations."

  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_LAUNCH_CONFIG_PUBLIC_IP_DISABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-password-policy" {
  count            = var.check_iam_password_policy ? 1 : 0
  name             = "iam-password-policy"
  description      = "Ensure the account password policy for IAM users meets the specified requirements"
  input_parameters = local.aws_config_iam_password_policy

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudtrail-enabled" {
  count       = var.check_cloudtrail_enabled ? 1 : 0
  name        = "cloudtrail-enabled"
  description = "Ensure CloudTrail is enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "multi-region-cloud-trail-enabled" {
  count       = var.check_multi_region_cloud_trail ? 1 : 0
  name        = "multi-region-cloud-trail-enabled"
  description = "Checks that there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match inputs parameters."

  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloud-trail-encryption-enabled" {
  count       = var.check_cloud_trail_encryption ? 1 : 0
  name        = "cloud-trail-encryption-enabled"
  description = "Checks whether AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer master key (CMK) encryption. The rule is COMPLIANT if the KmsKeyId is defined."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloud-trail-log-file-validation-enabled" {
  count       = var.check_cloud_trail_log_file_validation ? 1 : 0
  name        = "cloud-trail-log-file-validation-enabled"
  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudtrail-security-trail-enabled" {
  count       = var.check_cloudtrail_security_trail ? 1 : 0
  name        = "cloudtrail-security-trail-enabled"
  description = "Checks that there is at least one AWS CloudTrail trail defined with security best practices."

  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_SECURITY_TRAIL_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "instances-in-vpc" {
  count       = var.check_instances_in_vpc ? 1 : 0
  name        = "instances-in-vpc"
  description = "Ensure all EC2 instances run in a VPC"

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "root-account-mfa-enabled" {
  count       = var.check_root_account_mfa_enabled ? 1 : 0
  name        = "root-account-mfa-enabled"
  description = "Ensure root AWS account has MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "acm-certificate-expiration-check" {
  count            = var.check_acm_certificate_expiration_check ? 1 : 0
  name             = "acm-certificate-expiration-check"
  description      = "Ensures ACM Certificates in your account are marked for expiration within the specified number of days"
  input_parameters = local.aws_config_acm_certificate_expiration

  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-volume-inuse-check" {
  count       = var.check_ec2_volume_inuse_check ? 1 : 0
  name        = "ec2-volume-inuse-check"
  description = "Checks whether EBS volumes are attached to EC2 instances"

  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-imdsv2-check" {
  count       = var.check_ec2_imdsv2 ? 1 : 0
  name        = "ec2-imdsv2-check"
  description = "Checks if EC2 instances metadata is configured with IMDSv2 or not"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-instance-managed-by-systems-manager" {
  count       = var.check_ec2_instance_managed_by_systems_manager ? 1 : 0
  name        = "ec2-instance-managed-by-systems-manager"
  description = "Checks if the Amazon EC2 instances in your account are managed by AWS Systems Manager."

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-instance-no-public-ip" {
  count       = var.check_ec2_instance_no_public_ip ? 1 : 0
  name        = "ec2-instance-no-public-ip"
  description = "Checks if the Amazon EC2 instances in your account are managed by AWS Systems Manager."

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-instance-profile-attached" {
  count            = var.check_ec2_instance_profile_attached ? 1 : 0
  name             = "ec2-instance-profile-attached"
  description      = "Checks if an Amazon Elastic Compute Cloud (Amazon EC2) instance has an Identity and Access Management (IAM) profile attached to it."
  input_parameters = local.aws_config_ec2_instance_profile_attached

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_PROFILE_ATTACHED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-instances-in-vpc" {
  count            = var.check_ec2_instances_in_vpc ? 1 : 0
  name             = "ec2-instances-in-vpc"
  description      = "Checks if your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances."
  input_parameters = local.aws_config_ec2_instances_in_vpc

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ebs_snapshot_public_restorable" {
  count       = var.check_ebs_snapshot_public_restorable ? 1 : 0
  name        = "ebs-snapshot-public-restorable"
  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable"

  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-user-no-policies-check" {
  count       = var.check_iam_user_no_policies_check ? 1 : 0
  name        = "iam-user-no-policies-check"
  description = "Ensure that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-group-has-users-check" {
  count       = var.check_iam_group_has_users_check ? 1 : 0
  name        = "iam-group-has-users-check"
  description = "Checks whether IAM groups have at least one IAM user."

  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-storage-encrypted" {
  count       = var.check_rds_storage_encrypted ? 1 : 0
  name        = "rds-storage-encrypted"
  description = "Checks whether storage encryption is enabled for your RDS DB instances."

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-snapshot-encrypted" {
  count       = var.check_rds_snapshot_encrypted ? 1 : 0
  name        = "rds-snapshot-encrypted"
  description = "Checks whether Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted."

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOT_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-instance-public-access-check" {
  count       = var.check_rds_public_access ? 1 : 0
  name        = "rds-instance-public-access-check"
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item."

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-snapshots-public-prohibited" {
  count       = var.check_rds_snapshots_public_prohibited ? 1 : 0
  name        = "rds-snapshots-public-prohibited"
  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "guardduty-enabled-centralized" {
  count       = var.check_guard_duty ? 1 : 0
  name        = "guardduty-enabled-centralized"
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-public-write-prohibited" {
  count       = var.check_s3_bucket_public_write_prohibited ? 1 : 0
  name        = "s3-bucket-public-write-prohibited"
  description = "Checks that your S3 buckets do not allow public write access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eip_attached" {
  count       = var.check_eip_attached ? 1 : 0
  name        = "eip-attached"
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "required-tags" {
  count       = var.check_required_tags ? 1 : 0
  name        = "required-tags"
  description = "Checks if resources are deployed with configured tags."

  scope {
    compliance_resource_types = var.required_tags_resource_types
  }

  input_parameters = jsonencode(var.required_tags)

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "approved-amis-by-tag" {
  count            = var.check_approved_amis_by_tag ? 1 : 0
  name             = "approved-amis-by-tag"
  description      = "Checks whether running instances are using specified AMIs. Running instances that dont have at least one of the specified tags are noncompliant"
  input_parameters = local.aws_config_ami_approved_tag

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_TAG"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-encrypted-volumes" {
  count       = var.check_ec2_encrypted_volumes ? 1 : 0
  name        = "ec2-volumes-must-be-encrypted"
  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudwatch_log_group_encrypted" {
  count = var.check_cloudwatch_log_group_encrypted ? 1 : 0

  name        = "cloudwatch_log_group-encrypted"
  description = "Checks whether a log group in Amazon CloudWatch Logs is encrypted. The rule is NON_COMPLIANT if CloudWatch Logs has a log group without encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cw_loggroup_retention_period_check" {
  count = var.check_cw_loggroup_retention_period ? 1 : 0

  name        = "cloudwatch_log_group-retention"
  description = "Checks whether Amazon CloudWatch LogGroup retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period is not set or is less than the configured retention period."

  input_parameters = local.aws_config_cloudwatch_log_group_retention_period

  source {
    owner             = "AWS"
    source_identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_root_access_key" {
  count = var.check_iam_root_access_key ? 1 : 0

  name        = "iam-root-access-key"
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "vpc_default_security_group_closed" {
  count = var.check_vpc_default_security_group_closed ? 1 : 0

  name        = "vpc-default-security-group-closed"
  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic"

  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "s3-bucket-ssl-requests-only"
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "mfa_enabled_for_iam_console_access" {
  count = var.check_mfa_enabled_for_iam_console_access ? 1 : 0

  name        = "mfa-enabled-for-iam-console-access"
  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is compliant if MFA is enabled."

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "restricted_ssh" {
  count = var.check_restricted_ssh ? 1 : 0

  name        = "restricted-ssh"
  description = "Checks whether security groups that are in use disallow unrestricted incoming SSH traffic."

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eks-endpoint-no-public-access" {
  count       = var.check_eks_endpoint_no_public_access ? 1 : 0
  name        = "eks-endpoint-no-public-access"
  description = "Checks whether Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible."

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eks-secrets-encrypted" {
  count            = var.check_eks_secrets_encrypted ? 1 : 0
  name             = "eks-secrets-encrypted"
  description      = "Checks if Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using AWS Key Management Service (KMS) keys."
  input_parameters = local.aws_config_eks_secrets_encrypted

  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "kms-cmk-not-scheduled-for-deletion" {
  count            = var.check_kms_cmk_not_scheduled_for_deletion ? 1 : 0
  name             = "kms-cmk-not-scheduled-for-deletion"
  description      = "Checks if AWS KMS keys (KMS keys) are not scheduled for deletion in AWS Key Management Service (AWS KMS)."
  input_parameters = local.aws_config_kms_cmk_not_scheduled_for_deletion

  source {
    owner             = "AWS"
    source_identifier = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "service-vpc-endpoint-enabled" {
  for_each         = toset(var.vpc_endpoint_service_names)
  name             = "service-vpc-endpoint-enabled-${each.value}"
  description      = "Checks whether Service Endpoint for the ${each.value} service is created for each Amazon VPC."
  input_parameters = "{\"serviceName\": \"${each.value}\"}"

  source {
    owner             = "AWS"
    source_identifier = "SERVICE_VPC_ENDPOINT_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}