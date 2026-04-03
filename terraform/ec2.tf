# File: terraform/ec2.tf

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
 
resource "aws_security_group" "bad_sg" {
  name        = "lab-bad-security-group"
  description = "Intentionally misconfigured for security lab"
 
  ingress {
    description = "SSH open to internet — INTENTIONAL LAB MISCONFIG"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  tags = { Name = "lab-bad-sg", Project = "security-lab" }
}
 
resource "aws_instance" "lab_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.lab_profile.name
  vpc_security_group_ids = [aws_security_group.bad_sg.id]
 
  tags = { Name = "lab-vulnerable-server", Project = "security-lab" }
}
 
output "server_public_ip" {
  value       = aws_instance.lab_server.public_ip
  description = "Public IP of the lab server"
}