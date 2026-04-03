# File: terraform/cloudtrail.tf

data "aws_caller_identity" "current" {}
 
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.lab_bucket.id
 
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${aws_s3_bucket.lab_bucket.id}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${aws_s3_bucket.lab_bucket.id}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}
 
resource "aws_cloudtrail" "lab_trail" {
  name                          = "lab-audit-trail"
  s3_bucket_name                = aws_s3_bucket.lab_bucket.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true   
  is_multi_region_trail         = true   
  enable_log_file_validation    = true   
 
  tags = { Name = "lab-audit-trail", Project = "security-lab" }
 
  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}