# File: scripts/auto_remediate.py
# Purpose: Automatically fix all 3 cloud misconfigurations
# This simulates an automated cloud security response workflow
 
import boto3
import json
from datetime import datetime
 
s3  = boto3.client('s3',  region_name='us-east-1')
iam = boto3.client('iam', region_name='us-east-1')
ec2 = boto3.client('ec2', region_name='us-east-1')
 
BUCKET_NAME = 'aws-cloud-security-lab-dhanuka-2026'  
IAM_ROLE    = 'lab-ec2-role'
 
results = []
timestamp = datetime.utcnow().isoformat()
 
print('='*65)
print(' AUTOMATED CLOUD REMEDIATION SCRIPT')
print(f' Started: {timestamp}')
print('='*65)
 
# ── FIX 1: Block public access on S3 bucket ───────────────────
print('\n[FIX 1] Blocking public access on S3 bucket...')
print(f'  Target bucket: {BUCKET_NAME}')
try:
    # First — record the current (bad) state
    before = s3.get_public_access_block(Bucket=BUCKET_NAME)
    config = before['PublicAccessBlockConfiguration']
    print(f'  BEFORE: BlockPublicAcls={config["BlockPublicAcls"]} (should be True)')
 
    # Apply the fix
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls':       True,
            'IgnorePublicAcls':      True,
            'BlockPublicPolicy':     True,
            'RestrictPublicBuckets': True
        }
    )
 
    # Verify the fix worked
    after = s3.get_public_access_block(Bucket=BUCKET_NAME)
    config_after = after['PublicAccessBlockConfiguration']
    print(f'  AFTER:  BlockPublicAcls={config_after["BlockPublicAcls"]} (fixed!)')
    print(f'  STATUS: REMEDIATED')
    results.append({'finding':'S3 Public Access','status':'REMEDIATED',
                    'resource':BUCKET_NAME,'mitre':'T1530','cis':'CIS 2.1.5'})
except Exception as e:
    print(f'  ERROR: {e}')
    results.append({'finding':'S3 Public Access','status':'ERROR','error':str(e)})
 
# ── FIX 2: Remove AdministratorAccess from IAM role ───────────
print('\n[FIX 2] Removing overprivileged IAM policy...')
print(f'  Target role: {IAM_ROLE}')
try:
    # Detach the dangerous policy
    iam.detach_role_policy(
        RoleName=IAM_ROLE,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    print('  Removed: AdministratorAccess (all permissions)')
 
    # Attach a minimal policy instead (principle of least privilege)
    iam.attach_role_policy(
        RoleName=IAM_ROLE,
        PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
    )
    print('  Attached: AmazonS3ReadOnlyAccess (minimum required)')
    print('  STATUS: REMEDIATED — least privilege applied')
    results.append({'finding':'IAM Overprivilege','status':'REMEDIATED',
                    'resource':IAM_ROLE,'mitre':'T1078','cis':'CIS 1.16'})
except Exception as e:
    print(f'  ERROR: {e}')
    results.append({'finding':'IAM Overprivilege','status':'ERROR','error':str(e)})
 
# ── FIX 3: Remove open SSH rule from security group ───────────
print('\n[FIX 3] Revoking unrestricted SSH access...')
try:
    # Find the security group by name
    sgs = ec2.describe_security_groups(
        Filters=[{'Name':'group-name','Values':['lab-bad-security-group']}]
    )
    sg_id = sgs['SecurityGroups'][0]['GroupId']
    print(f'  Target security group: {sg_id}')
 
    # Remove the 0.0.0.0/0 SSH rule
    ec2.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort':   22,
            'ToPort':     22,
            'IpRanges':   [{'CidrIp':'0.0.0.0/0'}]
        }]
    )
    print('  Removed: TCP 22 from 0.0.0.0/0 (entire internet)')
    print('  STATUS: REMEDIATED — port 22 no longer exposed')
    results.append({'finding':'Unrestricted SSH','status':'REMEDIATED',
                    'resource':sg_id,'mitre':'T1133','cis':'CIS 5.2'})
except Exception as e:
    print(f'  ERROR: {e}')
    results.append({'finding':'Unrestricted SSH','status':'ERROR','error':str(e)})
 
# ── Summary report ────────────────────────────────────────────
print('\n' + '='*65)
print(' REMEDIATION COMPLETE')
print('='*65)
remediated = sum(1 for r in results if r['status']=='REMEDIATED')
print(f' {remediated}/{len(results)} findings remediated')
for r in results:
    icon = 'FIXED' if r['status']=='REMEDIATED' else 'ERROR'
    print(f'  [{icon}] {r["finding"]} — MITRE {r.get("mitre","N/A")} — CIS {r.get("cis","N/A")}')
 
# Save the remediation report
report = { 'timestamp': timestamp, 'analyst': 'Dhanuka Gunasekara',
           'tool': 'boto3 auto-remediation', 'results': results }
with open('reports/remediation_report.json','w') as f:
    json.dump(report, f, indent=2)
print('\nReport saved to reports/remediation_report.json')