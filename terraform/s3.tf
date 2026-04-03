# File: terraform/s3.tf
 
# The bucket itself
resource "aws_s3_bucket" "lab_bucket" {
  bucket = "aws-cloud-security-lab-dhanuka-2026"
 
  tags = {
    Name        = "aws-cloud-security-lab"
    Project     = "security-lab"
    Environment = "testing"
  }
}
 
resource "aws_s3_bucket_public_access_block" "bad_config" {
  bucket                  = aws_s3_bucket.lab_bucket.id
  block_public_acls       = false   # INSECURE — should be true
  block_public_policy     = false   # INSECURE — should be true
  ignore_public_acls      = false   # INSECURE — should be true
  restrict_public_buckets = false   # INSECURE — should be true
}
 
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.lab_bucket.id
  versioning_configuration { status = "Enabled" }
}
 
output "bucket_name" {
  value       = aws_s3_bucket.lab_bucket.id
  description = "The name of the lab S3 bucket"
}