# File: terraform/iam.tf

resource "aws_iam_role" "lab_ec2_role" {
  name = "lab-ec2-role"
 
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
 
  tags = { Name = "lab-ec2-role", Project = "security-lab" }
}
 
resource "aws_iam_role_policy_attachment" "bad_policy" {
  role       = aws_iam_role.lab_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
 
resource "aws_iam_instance_profile" "lab_profile" {
  name = "lab-ec2-profile"
  role = aws_iam_role.lab_ec2_role.name
}