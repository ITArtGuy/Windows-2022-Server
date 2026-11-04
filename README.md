# Windows Server 2022 Hardening on AWS EC2 🖥️

A hands-on security hardening project: I deployed a Windows Server 2022 instance in AWS and locked it down across 20 controls covering network exposure, accounts, legacy protocols, endpoint protection, credential protection, logging, and patching. Then I rebooted and verified that every control persisted.

*Completed for ISC 3033: Operating Systems Security, UT San Antonio (Fall 2026).*

---

## Environment

| Component | Value |
|---|---|
| Cloud | AWS EC2, region us-east-2 (Ohio) |
| Image | Microsoft Windows Server 2022 Base with NitroTPM and Secure Boot (`TPM-Windows_Server-2022-English-Full-Base`) |
| Instance type | t3.small (2 vCPU, 2 GB RAM), Nitro-based |
| Storage | 30 GiB gp3 EBS root volume |
| Access | RDP (TCP 3389), restricted by security group to a single /32 source IP |
| Tools | PowerShell 5.1, `net accounts`, `auditpol`, `secpol.msc`, `gpedit.msc`, `sconfig`, AWS console |

The NitroTPM/Secure Boot image was required because Credential Guard depends on a TPM and Secure Boot.

---

## What I hardened

| # | Control | Threat it addresses | Verified by |
|---|---|---|---|
| 1 | Launched a TPM + Secure Boot instance | Foundation for virtualization-based security | Instance Running, 2/2 status checks |
| 2 | Security group restricts RDP to my IP (/32) | Internet-wide RDP brute force and scanning | Single inbound rule, no `0.0.0.0/0` |
| 3 | Baselined OS, SID, integrity level | Establishes a before-state | `Get-ComputerInfo`, `whoami` |
| 4 | Required **IMDSv2** | SSRF-based theft of instance credentials | IMDSv1 returns **401**; token request succeeds |
| 5 | Audited local accounts, Guest disabled | Unused or passwordless accounts | `Get-LocalUser` |
| 6 | Named administrator account | Shared-login accountability gap | Account in Administrators group |
| 7 | Password policy: 14 char min, 24 history, complexity | Weak and reused passwords | `net accounts`, `secpol.msc` |
| 8 | Lockout: 5 attempts / 15 min | Online password guessing | `net accounts` |
| 9 | UAC: consent on secure desktop for all elevations | Silent elevation, auto-elevate UAC bypasses | Registry values 1 / 2 / 1 |
| 10 | SMBv1 removed | EternalBlue / WannaCry class exploits | `FS-SMB1` Available, `EnableSMB1Protocol` False |
| 11 | SMB signing required and encryption on | NTLM relay, traffic tampering, eavesdropping | `RequireSecuritySignature` True |
| 12 | PowerShell 2.0 removed | Downgrade attacks that bypass logging and AMSI | `PowerShell-V2` Removed |
| 13 | No LM hashes; NTLMv2 only (`LmCompatibilityLevel` 5) | LM hash cracking, NTLMv1 capture | Registry values 1 / 5 |
| 14 | Audited listening ports; disabled SSDP, UPnP, Remote Registry | Unneeded attack surface | `Get-NetTCPConnection`, `Get-Service` |
| 15 | Verified Defender AV real-time protection, forced signature update | Known malware | `Get-MpComputerStatus` |
| 16 | Three **ASR rules** in Block mode | LSASS credential theft, vulnerable driver abuse, WMI persistence | Three GUIDs with action `1` |
| 17 | Windows Firewall: all profiles on, default inbound Block, logging on | Lateral movement, unexpected listeners | `Get-NetFirewallProfile` |
| 18 | **LSA Protection** (RunAsPPL) and **Credential Guard** | Mimikatz-style credential dumping | `RunAsPPL` 2; `SecurityServicesRunning` {1} |
| 19 | Audit policy and PowerShell script block logging | No evidence after a breach; obfuscated commands | `auditpol`, Event ID **4104** |
| 20 | Windows Update policy: auto download and install, daily 3 AM | Unpatched vulnerabilities | Registry policy, `Get-HotFix` |
| 21 | Reboot and full verification sweep | Settings that don't persist | All values hardened post-reboot |

---

## Key commands

All PowerShell commands run in an elevated window.

**IMDSv2 check (Step 4)**
```powershell
# Should FAIL with 401 once IMDSv2 is required
Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-id" -TimeoutSec 5

# Correct IMDSv2 flow: get a token with PUT, then send it as a header
$token = Invoke-RestMethod -Uri "http://169.254.169.254/latest/api/token" -Method PUT -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"="21600"}
Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-id" -Headers @{"X-aws-ec2-metadata-token"=$token}
```

**Named admin account (Step 6)**
```powershell
$pw = Read-Host -AsSecureString -Prompt "Enter a strong password"
New-LocalUser -Name "lastname_adm" -Password $pw -FullName "First Last (Admin)" -Description "Named admin account" -PasswordNeverExpires:$false
Add-LocalGroupMember -Group "Administrators" -Member "lastname_adm"
```

**Password and lockout policy (Steps 7 and 8)**
```
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

**UAC (Step 9)**
```powershell
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $sys -Name "EnableLUA" -Value 1
Set-ItemProperty -Path $sys -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path $sys -Name "PromptOnSecureDesktop" -Value 1
```

**SMB (Steps 10 and 11)**
```powershell
Uninstall-WindowsFeature -Name FS-SMB1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -EncryptData $true -Force
```

**PowerShell 2.0, LM hash, NTLM (Steps 12 and 13)**
```powershell
Uninstall-WindowsFeature -Name PowerShell-V2
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
New-ItemProperty -Path $lsa -Name "NoLMHash" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $lsa -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWORD -Force
```

**Services and ports (Step 14)**
```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize
Set-Service -Name "SSDPSRV" -StartupType Disabled
Set-Service -Name "upnphost" -StartupType Disabled
Set-Service -Name "RemoteRegistry" -StartupType Disabled
```

**ASR rules (Step 16)**: use `Add-MpPreference`, not `Set-MpPreference`, which overwrites existing rules.
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled  # LSASS credential theft
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled  # Vulnerable signed drivers
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled  # WMI persistence
```

**Firewall (Step 17)**: order matters. Allow RDP **before** blocking inbound.
```powershell
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain, Public, Private -LogBlocked True -LogMaxSizeKilobytes 16384
```

**LSA Protection (Step 18)**
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 2 -PropertyType DWORD -Force
```
Credential Guard was enabled in `gpedit.msc` → Computer Configuration → Administrative Templates → System → Device Guard → **Turn On Virtualization Based Security**: Enabled; Secure Boot and DMA Protection; code integrity (HVCI) **Disabled** (not supported with Credential Guard on EC2); Credential Guard **Enabled without lock**.

**Logging (Step 19)**
```
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```
```powershell
$sbl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sbl -Force | Out-Null
New-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 3
```

**Windows Update policy (Step 20)**
```powershell
$au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path $au -Force | Out-Null
New-ItemProperty -Path $au -Name "NoAutoUpdate" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $au -Name "AUOptions" -Value 4 -PropertyType DWORD -Force
New-ItemProperty -Path $au -Name "ScheduledInstallDay" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $au -Name "ScheduledInstallTime" -Value 3 -PropertyType DWORD -Force
```

**Post-reboot verification (Step 21)**
```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL, NoLMHash, LmCompatibilityLevel
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
Get-LocalUser | Select-Object Name, Enabled
```

---

## Results

After rebooting, every control reported its hardened value:

- SMB1 disabled; SMB signing required; encryption on
- All three firewall profiles enabled with default inbound **Block**
- Defender real-time protection on
- `RunAsPPL` = 2, `NoLMHash` = 1, `LmCompatibilityLevel` = 5
- `SecurityServicesRunning` = **{1}**: Credential Guard running (it showed configured but not running before the reboot, as expected)
- Only the built-in Administrator and the named admin account enabled

---

## Troubleshooting and lessons learned

Real problems I hit and how I solved them:

| Problem | Cause | Fix |
|---|---|---|
| RDP "can't connect" after restarting the instance | Stopping an instance releases its auto-assigned public IP; the old `.rdp` file pointed to the old address | Download a fresh `.rdp` file after each start (an Elastic IP avoids this in production) |
| RDP login rejected from a different PC | The client filled in the local machine's username | Log in as `.\Administrator` (the `.\` targets the server's local account) |
| `ParameterBindingException` and "invalid HTTP Header characters" | Copying commands from a PDF inserted spaces (`- Headers`, `meta- data`) and merged two commands onto one line | Retype commands; never include the `PS C:\>` prompt |
| `RunAsPPL` showed `2-PropertyTypeDWORD` | Missing space joined the parameters, creating a **string** instead of a DWORD | Rewrote it with `New-ItemProperty ... -PropertyType DWORD -Force`; checked with `.GetValueKind()` |
| `auditpol` Error 0x00000057 | No spaces between `/set`, `/category`, and the other options | Add a space before each `/` option |
| Blank columns in verification output | Misspelled property names (`EnabledSecuritySignature`, `RunAsPPI`) | PowerShell's `Select-Object` silently returns empty columns for properties that don't exist, so check the headers |

**Takeaways**
- **Verify running state, not just configuration.** A registry value shows what was set; `SecurityServicesRunning` or Wininit Event 12 shows what's actually active.
- **Order of operations matters for remote access.** Allow your management protocol before default-deny, the same as allowing SSH before enabling UFW on Linux.
- **Layer controls at different levels.** The AWS security group blocks traffic before it reaches Windows and can't be changed by an attacker on the server; the Windows Firewall covers what gets past it.
- **Legacy compatibility is attack surface.** SMB1, PowerShell 2.0, LM hashes, and NTLMv1 all stayed available for years for compatibility, and attackers relied on each.

---

## Skills demonstrated

- AWS EC2 deployment, security groups, IMDSv2, EBS, NitroTPM
- Windows Server administration with PowerShell, registry, Local Security Policy, and Group Policy
- Identity hardening: account auditing, password and lockout policy, UAC, NTLM restrictions
- Attack surface reduction: legacy protocol removal, service and port auditing, ASR rules, host firewall
- Credential protection: LSA Protection, virtualization-based security, Credential Guard
- Security monitoring: Windows audit policy and PowerShell script block logging
- Mapping controls to real attacks: EternalBlue/WannaCry, the Capital One SSRF breach, NTLM relay, Mimikatz, PowerShell downgrade
- Systematic troubleshooting of command errors and connectivity

---

## References

- [Credential Guard for Windows instances, AWS EC2 User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/credential-guard.html)
- [Defense in depth with IMDSv2, AWS Security Blog (Nov 2019)](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [How Credential Guard works, Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works)
- [SMB security enhancements, Microsoft Learn](https://learn.microsoft.com/ro-ro/windows-server/storage/file-server/smb-security)
- [Attack surface reduction rules overview, Microsoft Learn](https://learn.microsoft.com/et-ee/defender-endpoint/attack-surface-reduction)
- [Service overview and network port requirements for Windows, Microsoft Learn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
- [Investigation: WannaCry cyber attack and the NHS, UK National Audit Office (2017)](https://nao.org.uk/wp-content/uploads/2017/10/Investigation-WannaCry-cyber-attack-and-the-NHS.pdf)
