data "aws_partition" "current" {}
data "aws_region" "current" {}
locals {
  create = var.create
  region = data.aws_region.current.name
  is_t_instance_type = replace(var.instance_type, "/^t(2|3|3a|4g){1}\\..*$/", "1") == "1" ? true : false
  ami = try(coalesce(var.ami, try(nonsensitive(data.aws_ssm_parameter.lookup_ami[0].value), null)), null)
  security_group_ids = var.vpc_security_group_ids != null ? var.vpc_security_group_ids : [aws_security_group.security_group[0].id]

  vpc_id = var.vpc_id != null ? var.vpc_id : try(nonsensitive(data.aws_ssm_parameter.lookup_vpc_id[0].value), null)
  subnet_id = var.subnet_id != null ? var.subnet_id : try(nonsensitive(data.aws_ssm_parameter.lookup_subnet_id[0].value), null)
  user_data = var.user_data != null ? var.user_data : ""
  validate_bootstrap_script = <<EOF
      TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
      INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/instance-id)
      aws ec2 create-tags --resources $INSTANCE_ID --tags Key=Bootstrap,Value=Successful --region ${local.region} 
  EOF

}

data "aws_ssm_parameter" "lookup_ami" {
  count = local.create && var.ami == null ? 1 : 0

  name = var.ami_ssm_parameter
}

data "aws_ssm_parameter" "lookup_subnet_id" {
  count = local.create && var.subnet_id == null ? 1 : 0

  name = "/platform/network/subnet_a"
}

data "aws_ssm_parameter" "lookup_vpc_id" {
  count = local.create && var.vpc_id == null ? 1 : 0

  name = "/platform/network/vpc_id"
}

################################################################################
# Instance
################################################################################

module "ec2" {
  # source = "../ec2-base/"
  source = "git::https://github.com/stercamp/tf-aws-modules-catalog//ec2-base"
  count = local.create ? 1 : 0

  name = "${var.name}"

  ami                  = local.ami
  instance_type        = var.instance_type
  user_data                   = <<-EOT
    #!/bin/bash
    ${local.user_data}
    ${local.validate_bootstrap_script}
  EOT
  subnet_id = local.subnet_id


  # iam_instance_profile = aws_iam_instance_profile.this[0].id
  create_iam_instance_profile = false
  iam_instance_profile = var.iam_instance_profile
  
  # Modified to use exisitng InstanceProfile
  # iam_role_name = "${var.name}-ec2-role"
  # iam_role_name = var.iam_role_name

  metadata_options = {
    "http_endpoint"               = "enabled"
    "http_put_response_hop_limit" = 1
    "http_tokens"                 = "required"
  }
  vpc_security_group_ids = local.security_group_ids
}

################################################################################
# EC2 bootstrap validation
################################################################################

resource "null_resource" "validate_bootstrap" {
  count = local.create ? 1 : 0

  provisioner "local-exec" {
    command = <<EOT
      max_attempts=3
      sleep_time=60
      attempt=0
      while [ $attempt -lt $max_attempts ]; do
        tags=$(aws ec2 describe-tags --filters "Name=resource-id,Values=${module.ec2[0].id}" --query "Tags[?Key=='Bootstrap'].Value" --region ${local.region} --output text)
        if [ "$tags" == "Successful" ]; then
          echo "Instance bootstrap validation succeeded"
          exit 0
        fi
        echo "Attempt $((attempt+1))/$max_attempts: Bootstrap tag not found, retrying in $sleep_time seconds..."
        attempt=$((attempt+1))
        sleep $sleep_time
      done
      echo "Instance bootstrap validation failed after $max_attempts attempts"
      exit 1
    EOT
  }

  triggers = {
    instance_id = module.ec2[0].id
  }

  depends_on = [module.ec2]
}

################################################################################
# Security Group
################################################################################

resource "random_uuid" "random_identifier" {
    count = var.vpc_security_group_ids == null ? 1 : 0
    keepers = {
       # ensure that uuid is made one time only
       const = "persistent-uuid"
    }
}
resource "aws_security_group" "security_group" {
  count = var.vpc_security_group_ids == null ? 1 : 0
  name        = "${var.name}-${random_uuid.random_identifier[0].result}"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = local.vpc_id
  tags = {
    Name = "${var.name}-security-group"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allowed_ingress" {
  count = var.vpc_security_group_ids == null ? 1 : 0
  security_group_id = aws_security_group.security_group[0].id
  cidr_ipv4         = "10.10.10.10/32"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

# resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv6" {
#   security_group_id = aws_security_group.allow_tls.id
#   cidr_ipv6         = aws_vpc.main.ipv6_cidr_block
#   from_port         = 443
#   ip_protocol       = "tcp"
#   to_port           = 443
# }

# resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
#   security_group_id = aws_security_group.allow_tls.id
#   cidr_ipv4         = "0.0.0.0/0"
#   ip_protocol       = "-1" # semantically equivalent to all ports
# }