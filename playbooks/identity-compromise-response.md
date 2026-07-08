# Identity Compromise Response Playbook

## Trigger
Suspicious identity activity detected through KQL hunting or SIEM alerts.

## Objective
Contain identity-based attacks such as account takeover, privilege escalation, or lateral movement.

## Steps

### 1. Validate the Alert
- Review authentication logs  
- Check for unusual MFA prompts  
- Confirm user activity patterns  

### 2. Contain the Identity
- Disable compromised account  
- Reset credentials  
- Revoke active sessions  

### 3. Investigate Scope
- Review lateral movement attempts  
- Check privilege escalation events  
- Analyze cloud identity logs  

### 4. Remediate
- Enforce MFA  
- Rotate secrets  
- Apply Conditional Access policies  

### 5. Document & Close
- Record incident details  
- Update ATT&CK coverage matrix  
- Add new detections if gaps found  
