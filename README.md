# Kikoku

**Advanced Active Directory Security Audit & Analysis Tool**

Named after the cursed blade that finds hidden paths - perfect for ACL traversal and attack path discovery in Active Directory environments.

![Version](https://img.shields.io/badge/version-2.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Overview

Kikoku is a comprehensive, standalone Active Directory security auditing tool that performs deep analysis of AD environments to identify security misconfigurations, attack paths, and potential vulnerabilities. Unlike other AD audit tools, Kikoku requires **NO dependencies** on the ActiveDirectory PowerShell module - it uses raw LDAP queries for maximum compatibility.

## ✨ Key Features

- **🔍 60+ Security Audit Checks** - Comprehensive security analysis
- **🛡️ ACL Traversal** - BloodHound-style group membership path analysis
- **🔗 Attack Path Discovery** - Finds indirect permissions through nested groups
- **📊 Beautiful Output** - Color-coded findings with severity ratings
- **🚀 Standalone** - No ActiveDirectory PowerShell module required
- **⚡ LDAP Direct** - Uses raw LDAP queries via System.DirectoryServices
- **🎨 Professional UI** - ASCII art banner and formatted output

## 🚀 Quick Start

### Basic Usage

```powershell
# Uses current logged-in user's credentials automatically
.\Kikoku.ps1
```

### Advanced Usage

```powershell
# Specify domain
.\Kikoku.ps1 -Domain contoso.com

# Use specific credentials
$Cred = Get-Credential
.\Kikoku.ps1 -Domain contoso.com -Credential $Cred

# Show detailed findings
.\Kikoku.ps1 -Detailed

# Specify domain controller
.\Kikoku.ps1 -DomainController dc01.contoso.com
```

## 📋 What Kikoku Audits

### Core Security Checks
- ✅ User enumeration and analysis
- ✅ Group enumeration and membership
- ✅ Computer enumeration
- ✅ Password policy analysis
- ✅ Trust analysis
- ✅ Delegation analysis (Unconstrained, Constrained, RBCD)
- ✅ Kerberoastable account detection
- ✅ AS-REP roastable account detection
- ✅ Shadow admins detection
- ✅ Service account analysis

### Advanced Security Features
- ✅ **ACL Traversal** - Finds attack paths through group memberships
- ✅ **DCSync Shadow Permissions** - Detects DCSync via nested groups
- ✅ **gMSA Password Retrieval** - Who can read gMSA passwords
- ✅ **GPO Delegation** - Dangerous GPO ACLs
- ✅ **Tiered Administration** - Tier0 violations
- ✅ **Kerberos Hardening** - krbtgt password age
- ✅ **LDAP/NTLM Hardening** - Security configuration analysis
- ✅ **Exchange Security** - Exchange Trusted Subsystem analysis
- ✅ **DNS Security** - DNSAdmins group analysis
- ✅ **FSMO/DC Health** - Domain controller security
- ✅ **ADCS Vulnerabilities** - ESC8/ESC9/ESC10 detection
- ✅ **SCCM/MECM Security** - Configuration Manager analysis
- ✅ **Cloud Identity** - PTA/SSO account analysis
- ✅ And 40+ more security checks...

## 🎨 Features

### ACL Traversal (BloodHound-style)
Kikoku performs deep ACL traversal to find indirect permissions:

```
User A → Member of → Group A → Member of → Group B → has GenericWrite on Domain Root
```

This helps identify attack paths that might not be immediately obvious.

### Standalone Operation
- **No ActiveDirectory Module Required** - Works on any Windows system
- **Raw LDAP Queries** - Direct LDAP access via System.DirectoryServices
- **Automatic Credential Handling** - Uses current logged-in user by default

### Beautiful Output
- Color-coded severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Formatted section headers
- Summary statistics
- Professional ASCII art banner

## 📊 Output Example

```
        ██╗  ██╗██╗██╗  ██╗ ██████╗ ██╗  ██╗██╗   ██╗
        ██║ ██╔╝██║██║ ██╔╝██╔═══██╗██║ ██╔╝██║   ██║
        █████╔╝ ██║█████╔╝ ██║   ██║█████╔╝ ██║   ██║
        ██╔═██╗ ██║██╔═██╗ ██║   ██║██╔═██╗ ██║   ██║
        ██║  ██╗██║██║  ██╗╚██████╔╝██║  ██╗╚██████╔╝
        ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 

    ╔═══════════════════════════════════════════════════════════════════╗
    ║          ADVANCED ACTIVE DIRECTORY SECURITY AUDIT TOOL           ║
    ║                    STANDALONE EDITION v2.0                      ║
    ╚═══════════════════════════════════════════════════════════════════╝

    Creator: 4vian | Version: 2.0
```

## 🔧 Requirements

- **PowerShell 5.1+**
- **Windows** (tested on Windows 10/11 and Windows Server 2016+)
- **Domain Access** - Must be able to connect to Active Directory via LDAP
- **No Additional Modules** - Works standalone!

## 📖 Documentation

See [Feature.md](Feature.md) for complete feature list and detailed documentation.

## ⚠️ Disclaimer

**AUTHORIZED USE ONLY** - This tool is intended for legitimate security audits and red team exercises. Only use on systems you own or have explicit permission to test.

## 👤 Creator

**4vian**

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Issues

Found a bug or have a feature request? Please open an issue on GitHub.

## ⭐ Features in Detail

### Attack Path Detection
- ACL traversal with group membership analysis
- Indirect permission discovery
- Full path visualization (User → Group → Group → has Right)

### Security Analysis
- 60+ security checks
- Vulnerability detection
- Misconfiguration identification
- Risk assessment with severity ratings

### Enumeration
- Complete AD object enumeration
- User, Group, Computer analysis
- GPO, OU, Trust enumeration
- Service account identification

## 🔍 Comparison with Other Tools

| Feature | Kikoku | Other Tools |
|---------|--------|-------------|
| Standalone (No AD Module) | ✅ | ❌ |
| ACL Traversal | ✅ | Limited |
| LDAP Direct Queries | ✅ | ❌ |
| 60+ Security Checks | ✅ | Varies |
| Beautiful Output | ✅ | Varies |
| Attack Path Visualization | ✅ | Limited |

## 📚 Usage Tips

1. **Run with Elevated Privileges** - Some checks require elevated permissions
2. **Use -Detailed Flag** - For comprehensive output with all details
3. **Specify Domain Controller** - For faster queries in large domains
4. **Review Findings** - Pay special attention to CRITICAL and HIGH severity findings

## 🎯 Use Cases

- **Security Audits** - Comprehensive AD security assessment
- **Red Team Exercises** - Identify attack paths and vulnerabilities
- **Compliance Checks** - Verify security configurations
- **Penetration Testing** - Find security misconfigurations
- **Blue Team** - Understand AD security posture

---

**Made with ❤️ by 4vian**

