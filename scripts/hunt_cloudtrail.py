# File: scripts/hunt_cloudtrail.py

import boto3
import json
from datetime import datetime, timedelta

client = boto3.client('cloudtrail', region_name='us-east-1')

print('='*65)
print(' CLOUDTRAIL THREAT HUNT — Cloud Security Lab')
print(f' Time: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC')
print('='*65)

findings = []

# ── HUNT 1: IAM privilege escalation ──────────────────────────────
print('\n[HUNT 1] Scanning for IAM privilege escalation...')
resp = client.lookup_events(
    LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':'AttachRolePolicy'}],
    StartTime=datetime.utcnow() - timedelta(hours=24),
    EndTime=datetime.utcnow()
)

for event in resp['Events']:
    d = json.loads(event['CloudTrailEvent'])
    policy = d['requestParameters']['policyArn']
    actor  = d['userIdentity']['arn']
    t      = event['EventTime'].strftime('%Y-%m-%d %H:%M:%S')

    sev = 'CRITICAL' if 'AdministratorAccess' in policy else 'MEDIUM'

    print(f'  [{sev}] IAM Policy Attached')
    print(f'          Actor:   {actor}')
    print(f'          Policy:  {policy}')
    print(f'          Time:    {t} UTC')
    print(f'          ATT&CK:  T1078 - Valid Accounts / TA0004 Privilege Escalation')

    findings.append({
        'severity':sev,
        'type':'IAM_PRIVILEGE_ESCALATION',
        'actor':actor,
        'resource':policy,
        'time':t,
        'mitre':'T1078',
        'tactic':'TA0004'
    })

if not resp['Events']:
    print('  No IAM policy attachment events found.')

# ── HUNT 2: S3 public access modification ────────────────────────
print('\n[HUNT 2] Scanning for S3 public access changes...')

resp2 = client.lookup_events(
    LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':'PutBucketPublicAccessBlock'}],
    StartTime=datetime.utcnow() - timedelta(hours=24),
    EndTime=datetime.utcnow()
)

for event in resp2['Events']:
    d = json.loads(event['CloudTrailEvent'])

    bucket = d['requestParameters']['bucketName']
    actor  = d['userIdentity']['arn']
    t      = event['EventTime'].strftime('%Y-%m-%d %H:%M:%S')

    print(f'  [HIGH] S3 Public Access Block Modified')
    print(f'          Actor:   {actor}')
    print(f'          Bucket:  {bucket}')
    print(f'          Time:    {t} UTC')
    print(f'          ATT&CK:  T1530 - Data from Cloud Storage Object')

    findings.append({
        'severity':'HIGH',
        'type':'S3_PUBLIC_ACCESS_CHANGE',
        'actor':actor,
        'resource':bucket,
        'time':t,
        'mitre':'T1530',
        'tactic':'TA0009'
    })

if not resp2['Events']:
    print('  No S3 public access changes found.')

# ── HUNT 3: Security group changes ───────────────────────────────
print('\n[HUNT 3] Scanning for security group rule changes...')

resp3 = client.lookup_events(
    LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':'AuthorizeSecurityGroupIngress'}],
    StartTime=datetime.utcnow() - timedelta(hours=24),
    EndTime=datetime.utcnow()
)

for event in resp3['Events']:
    d = json.loads(event['CloudTrailEvent'])

    actor = d['userIdentity']['arn']
    t     = event['EventTime'].strftime('%Y-%m-%d %H:%M:%S')

    rules = d.get('requestParameters',{}).get('ipPermissions',{}).get('items',[])

    for rule in rules:
        for ip_range in rule.get('ipRanges',{}).get('items',[]):
            if ip_range.get('cidrIp') == '0.0.0.0/0':

                print(f'  [HIGH] Security Group: Unrestricted Inbound Rule Added')
                print(f'          Actor:    {actor}')
                print(f'          Protocol: TCP Port {rule.get("fromPort")}')
                print(f'          CIDR:     0.0.0.0/0 (entire internet)')
                print(f'          Time:     {t} UTC')
                print(f'          ATT&CK:   T1133 - External Remote Services')

                findings.append({
                    'severity':'HIGH',
                    'type':'OPEN_SECURITY_GROUP',
                    'actor':actor,
                    'resource':'0.0.0.0/0',
                    'time':t,
                    'mitre':'T1133',
                    'tactic':'TA0001'
                })

if not resp3['Events']:
    print('  No security group ingress changes found.')

# ── HUNT 4: Root account usage ────────────────────────────────────
print('\n[HUNT 4] Checking for root account usage (always suspicious)...')

resp4 = client.lookup_events(
    LookupAttributes=[{'AttributeKey':'Username','AttributeValue':'root'}],
    StartTime=datetime.utcnow() - timedelta(hours=24),
    EndTime=datetime.utcnow()
)

if resp4['Events']:
    print(f'  [CRITICAL] Root account used {len(resp4["Events"])} time(s) in 24 hours!')

    for event in resp4['Events']:
        print(f'             Action: {event["EventName"]} at {event["EventTime"]}')

    findings.append({
        'severity':'CRITICAL',
        'type':'ROOT_ACCOUNT_USAGE',
        'mitre':'T1078.004'
    })

else:
    print('  PASS: No root account usage found in last 24 hours.')

# ── Summary ───────────────────────────────────────────────────────
print('\n' + '='*65)
print(f' HUNT COMPLETE — {len(findings)} finding(s) detected')
print('='*65)

for f in findings:
    print(f'  [{f["severity"]}] {f["type"]} — ATT&CK: {f["mitre"]}')

# Save results to JSON for the incident report
output = {
    'hunt_timestamp': datetime.utcnow().isoformat(),
    'total_findings': len(findings),
    'findings': findings
}

with open('reports/cloudtrail_hunt_results.json','w') as f:
    json.dump(output, f, indent=2)

print('\nResults saved to reports/cloudtrail_hunt_results.json')