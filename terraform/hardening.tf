######################################################################
# Gap-closing overrides on the starter's existing resources.
# Each block below is scoped to one GAPS.md entry — see WRITEUP.md's
# Control coverage table for the CMMC control it maps to.
######################################################################

# GAP-01: SSE-S3 -> SSE-KMS with the customer CMK from kms.tf.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-02: DynamoDB SSE has no standalone resource type in the AWS provider —
# it's a nested block on aws_dynamodb_table itself, so this gap is closed
# directly on that resource in main.tf, not here. See main.tf's
# aws_dynamodb_table.intake for the server_side_encryption block.
#
# Follow-on for GAP-01/GAP-02: the key policy in kms.tf only says "IAM
# controls access to this key" — it doesn't grant anyone that access. The
# Lambda's execution role needs its own explicit grant to actually use the
# CMK, or every read/write through the app breaks (confirmed via
# `make test` after applying GAP-02: kms:Decrypt AccessDeniedException).
resource "aws_iam_role_policy" "lambda_kms" {
  name = "intake-kms-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# GAP-03: deny any request to the uploads bucket that isn't over TLS.
resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-04: enable versioning so PHI overwrites/deletes are recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-05: security group for the Lambda, placed in the starter's existing
# VPC (see main.tf's aws_vpc.main / aws_subnet.private) rather than
# building a second one. Outbound-only: API Gateway invokes the function
# directly, nothing needs to reach it inbound over the network.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Intake Lambda - outbound only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Allow all outbound (DynamoDB/S3/KMS reached over the internet from a private subnet)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# GAP-05 (continued): the actual vpc_config is a nested block on
# aws_lambda_function itself, so it's added directly on that resource in
# main.tf, not here — same pattern as GAP-02's DynamoDB encryption.
#
# GAP-05 (continued again): placing a Lambda in a VPC requires its execution
# role to manage ENIs (CreateNetworkInterface / DescribeNetworkInterfaces /
# DeleteNetworkInterface) or the apply fails with InvalidParameterValueException.
# Same class of surprise as GAP-01/02's missing KMS grant: closing one gap
# exposes a permission the original role never needed.
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# GAP-05 (continued again): the private subnets have no NAT gateway, so a
# Lambda placed in them loses its route to DynamoDB/S3/KMS's public
# endpoints entirely (confirmed via `make test`: 10s hard timeout, no
# error). Chose VPC endpoints over a NAT gateway: cheaper, and keeps
# DynamoDB/S3/KMS traffic on the AWS backbone instead of routing out to
# the public internet and back — a better fit for SC.L2-3.13.1 (Boundary
# Protection) than "open a path out and back in."

# S3 and DynamoDB support free Gateway endpoints, attached to a route
# table rather than a subnet. The private subnets have no explicit route
# table association (see main.tf), so they use the VPC's main route table.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]
}

# KMS only offers an Interface endpoint (an ENI in the subnet, not a route
# table entry), so it needs its own security group allowing HTTPS in from
# the Lambda's security group.
resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name_prefix}-vpce-sg"
  description = "VPC interface endpoints - HTTPS from the Lambda SG only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from the intake Lambda"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  tags = { Name = "${local.name_prefix}-vpce-sg" }
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

# GAP-06: reserved concurrency, DLQ, X-Ray on the intake Lambda.
# reserved_concurrent_executions and tracing_config are nested
# arguments/blocks on aws_lambda_function itself, so those are set
# directly on that resource in main.tf, not here — same pattern as
# GAP-02/GAP-05. This file adds the two new resources those settings need:
# the DLQ queue and X-Ray's own VPC endpoint.

# Note on this DLQ: aws_lambda_function.dead_letter_config only catches
# failures from ASYNCHRONOUS invocations (S3/SNS/EventBridge triggers).
# This Lambda is invoked synchronously by API Gateway (AWS_PROXY,
# request/response) — a failure here returns straight to the caller and
# never reaches this queue. Added to satisfy the literal GAP-06 wording
# and its CMMC control mapping, but it is not a fully effective
# compensating control for this invocation path. A synchronous failure
# path would need Lambda Destinations on an async wrapper, or a queue
# in front of the Lambda, neither of which is in scope here.
resource "aws_sqs_queue" "intake_dlq" {
  name              = "${local.name_prefix}-intake-dlq-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.arn
}

resource "aws_iam_role_policy" "lambda_dlq" {
  name = "intake-dlq-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      }
    ]
  })
}

# X-Ray write access for the Lambda execution role (segments/telemetry).
resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Learned from GAP-05: anything the Lambda calls out to needs a route from
# the private subnets. X-Ray is no different — without this endpoint,
# tracing would be "enabled" but every segment would silently fail to
# send. Reuses the same interface-endpoint security group as KMS.
resource "aws_vpc_endpoint" "xray" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.xray"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
