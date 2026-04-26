# File: reports/CLOUD-IR-001.md
# INCIDENT REPORT — CLOUD-IR-001
 
| Field          | Details                                         |
|----------------|-------------------------------------------------|
| Report ID      | CLOUD-IR-001                                    |
| Severity       | HIGH                                            |
| Date Detected  | [26th April 2026]                           |
| Date Contained | [26th April 2026]                           |
| Analyst        | Dhanuka Gunasekara                              |
| Status         | CONTAINED & REMEDIATED                          |
| Environment    | AWS us-east-1 — Security Lab                    |
 
## Executive Summary
Three HIGH-severity cloud misconfigurations were identified in the AWS
lab environment using Prowler CSPM scanning and CloudTrail log analysis.
All findings were automatically remediated using a Python/boto3 script.
No data exfiltration was detected. A fake credentials file was exposed
in a public S3 bucket for the duration of the lab simulation.
 
## Attack Timeline
 
| Time (UTC)  | Event                                                  | Source       |
|-------------|--------------------------------------------------------|--------------|
| T+0:00      | Terraform deployed misconfigured infrastructure        | CloudTrail   |
| T+0:01      | S3 public access block disabled (T1530)                | CloudTrail   |
| T+0:01      | AdministratorAccess attached to IAM role (T1078)       | CloudTrail   |
| T+0:02      | SSH port 22 opened to 0.0.0.0/0 (T1133)               | CloudTrail   |
| T+0:05      | Fake credentials file uploaded to public bucket        | CloudTrail   |
| T+1:00      | Prowler CSPM scan — 3 HIGH findings detected           | Prowler      |
| T+1:30      | CloudTrail hunt — all 3 API events identified          | hunt script  |
| T+2:00      | GuardDuty enabled — continuous monitoring active       | AWS Console  |
| T+2:30      | AWS Config NON_COMPLIANT on 3 rules confirmed          | AWS Config   |
| T+3:00      | Auto-remediation script executed — all 3 fixed         | boto3 script |
| T+3:05      | All resources verified COMPLIANT post-remediation      | AWS Console  |
 
## Findings
 
### Finding 1 — S3 Bucket Public Access Exposed
- **Severity:** HIGH
- **Resource:** aws-cloud-security-lab-dhanuka-2026
- **MITRE ATT&CK:** T1530 — Data from Cloud Storage Object
- **CIS Benchmark:** CIS AWS 2.1.5
- **Risk:** Sensitive credential file accessible to unauthenticated users
- **Detection:** Prowler rule s3_bucket_public_access_block_enabled
- **Remediation:** boto3 put_public_access_block() — all 4 settings set to True
- **Verification:** AWS Console confirmed 'Block all public access: ON'
 
### Finding 2 — IAM Role with AdministratorAccess
- **Severity:** HIGH
- **Resource:** lab-ec2-role
- **MITRE ATT&CK:** T1078 — Valid Accounts / Privilege Escalation (TA0004)
- **CIS Benchmark:** CIS AWS 1.16
- **Risk:** EC2 server with admin access = full account takeover if compromised
- **Detection:** Prowler rule iam_no_administrator_access_with_sts_role
- **Remediation:** Detached AdministratorAccess; applied AmazonS3ReadOnlyAccess (least privilege)
- **Verification:** IAM Console confirmed policy change
 
### Finding 3 — Security Group: SSH Open to Internet
- **Severity:** HIGH
- **Resource:** lab-bad-security-group
- **MITRE ATT&CK:** T1133 — External Remote Services (TA0001 Initial Access)
- **CIS Benchmark:** CIS AWS 5.2
- **Risk:** SSH brute force and exploitation risk from any internet IP
- **Detection:** Prowler rule ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
- **Remediation:** boto3 revoke_security_group_ingress() — removed 0.0.0.0/0 TCP:22
- **Verification:** Security group inbound rules confirmed port 22 rule removed
 
## Root Cause Analysis
All three misconfigurations originated from the Terraform IaC deployment.
Infrastructure as Code deployments can propagate insecure defaults at scale.
This highlights the need for:
1. Pre-deployment IaC scanning (tools: Checkov, tfsec)
2. Continuous CSPM monitoring (tools: Prowler, AWS Config, AWS Security Hub)
3. Automated remediation pipelines for known misconfig patterns
 
## Lessons Learned
- Prowler detected all 3 HIGH findings in a single 10-minute scan
- CloudTrail provided full audit trail of every misconfiguration event
- Python/boto3 automated remediation reduced time-to-fix to under 30 seconds
- GuardDuty flagged Prowler scan activity — documented as false positive
- Before/after verification confirmed all 3 remediations were successful