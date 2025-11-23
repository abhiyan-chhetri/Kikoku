<#
.SYNOPSIS
    Kikoku - Comprehensive Active Directory Security Audit Tool
    
.DESCRIPTION
    KIKOKU - Advanced Active Directory Security Audit & Analysis Tool
    
    Named after the cursed blade that finds hidden paths - perfect for ACL traversal
    and attack path discovery in Active Directory environments.
    
    A comprehensive, standalone AD security auditing tool that performs deep analysis
    of Active Directory environments to identify security misconfigurations, attack
    paths, and potential vulnerabilities.
    
    Features:
    - NO DEPENDENCIES on ActiveDirectory PowerShell module
    - Uses raw LDAP queries (System.DirectoryServices)
    - ACL traversal with group membership analysis (BloodHound-style)
    - Finds indirect permissions through nested group memberships
    - Complete enumeration of all AD objects
    - 60+ security audit checks
    - Attack path identification and visualization
    - Beautiful formatted output with severity ratings
    
    This is a PENTESTING/AUDITING tool - detects vulnerabilities but does NOT extract credentials.

.AUTHOR
    4vian

.PARAMETER Domain
    Target domain (default: current domain)

.PARAMETER DomainController
    Specific domain controller to query

.PARAMETER Credential
    Credentials to use for authentication (default: current logged-in user)

.PARAMETER OutputPath
    Path to save detailed report (optional)

.PARAMETER Detailed
    Show detailed information for each finding

.EXAMPLE
    .\Kikoku.ps1
    # Uses current logged-in user's credentials automatically
    
.EXAMPLE
    .\Kikoku.ps1 -Domain contoso.com -Detailed
    # Uses current logged-in user's credentials for contoso.com domain
    
.EXAMPLE
    $Cred = Get-Credential
    .\Kikoku.ps1 -Domain contoso.com -Credential $Cred
    # Uses specified credentials

.NOTES
    AUTHORIZED USE ONLY - For legitimate security audits and red team exercises
    Creator: 4vian
    Version: 2.0
    This version is completely standalone - no ActiveDirectory module required
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainController = $null,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $null,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed = $false
)

#region Helper Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline = $false
    )
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "    ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "    ║ " -NoNewline -ForegroundColor Cyan
    Write-Host $Title.PadRight(71) -NoNewline -ForegroundColor White
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "    ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Finding {
    param(
        [string]$Title,
        [string]$Severity,
        [string]$Description,
        [object]$Details = $null
    )
    
    $SeverityColors = @{
        "CRITICAL" = "Red"
        "HIGH" = "Magenta"
        "MEDIUM" = "Yellow"
        "LOW" = "Gray"
        "INFO" = "Cyan"
    }
    
    $SeverityIcons = @{
        "CRITICAL" = "🔴"
        "HIGH" = "🟣"
        "MEDIUM" = "🟡"
        "LOW" = "⚪"
        "INFO" = "🔵"
    }
    
    $Color = $SeverityColors[$Severity]
    $Icon = $SeverityIcons[$Severity]
    if (-not $Color) { $Color = "White" }
    if (-not $Icon) { $Icon = "•" }
    
    Write-Host "    " -NoNewline
    Write-Host "$Icon " -NoNewline -ForegroundColor $Color
    Write-Host "[$Severity] " -ForegroundColor $Color -NoNewline
    Write-Host $Title -ForegroundColor White
    Write-Host "         └─ " -NoNewline -ForegroundColor DarkGray
    Write-Host $Description -ForegroundColor Gray
    
    if ($Details -and $Detailed) {
        if ($Details -is [array]) {
            foreach ($Item in $Details) {
                Write-Host "            • $Item" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "            • $Details" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

function Get-DomainDN {
    param([string]$Domain)
    $Parts = $Domain.Split('.')
    $DN = "DC=" + ($Parts -join ",DC=")
    return $DN
}

#endregion

#region LDAP Query Functions (Standalone)

function Invoke-LDAPQuery {
    param(
        [string]$SearchBase,
        [string]$LDAPFilter,
        [string[]]$Properties = @("*"),
        [string]$DC = $null,
        [System.Management.Automation.PSCredential]$Cred = $null
    )
    
    $Results = @()
    
    try {
        $Server = if ($DC) { $DC } else { $Domain }
        $LDAPPath = "LDAP://$Server/$SearchBase"
        
        $SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath)
        
        if ($Cred) {
            $SearchRoot.Username = $Cred.UserName
            $SearchRoot.Password = $Cred.GetNetworkCredential().Password
        }
        
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($SearchRoot)
        $Searcher.Filter = $LDAPFilter
        $Searcher.PageSize = 1000
        $Searcher.SizeLimit = 0
        
        if ($Properties -and $Properties[0] -ne "*") {
            foreach ($Property in $Properties) {
                $Searcher.PropertiesToLoad.Add($Property) | Out-Null
            }
        }
        
        $SearchResults = $Searcher.FindAll()
        
        foreach ($Result in $SearchResults) {
            $Dict = @{
                DistinguishedName = $Result.Properties["distinguishedName"][0]
            }
            
            foreach ($PropertyName in $Result.Properties.PropertyNames) {
                if ($Result.Properties[$PropertyName].Count -eq 1) {
                    $Dict[$PropertyName] = $Result.Properties[$PropertyName][0]
                } else {
                    $Values = @()
                    foreach ($Value in $Result.Properties[$PropertyName]) {
                        $Values += $Value
                    }
                    $Dict[$PropertyName] = $Values
                }
            }
            
            $Results += $Dict
        }
        
        $SearchRoot.Dispose()
        $Searcher.Dispose()
        
    } catch {
        Write-Warning "LDAP query failed: $_"
    }
    
    return $Results
}

#endregion

#region SDDL and ACL Parsing

function Parse-SDDL {
    param([string]$SDDL)
    
    $ACLEntries = @()
    
    if (-not $SDDL) {
        return $ACLEntries
    }
    
    # Parse SDDL format: D:(A;;GA;;;SID)
    # D: = DACL
    # A: = Allow
    # GA = Generic All
    # SID = Security Identifier
    
    $DACLPattern = 'D:\(([^)]+)\)'
    if ($SDDL -match $DACLPattern) {
        $DACL = $Matches[1]
        
        # Split by ACE entries
        $ACEPattern = '\(([^)]+)\)'
        $Matches = [regex]::Matches($DACL, $ACEPattern)
        
        foreach ($Match in $Matches) {
            $ACE = $Match.Groups[1].Value
            $Parts = $ACE -split ';'
            
            if ($Parts.Length -ge 4) {
                $ACEType = $Parts[0]  # A (Allow) or D (Deny)
                $ACEFlags = $Parts[1]
                $ACERights = $Parts[2]  # GA, GW, WD, etc.
                $ACEObjectType = $Parts[3]
                $ACEInheritedObjectType = $Parts[4]
                $ACESubject = $Parts[5]  # SID
                
                $ACLEntries += @{
                    Type = $ACEType
                    Flags = $ACEFlags
                    Rights = $ACERights
                    ObjectType = $ACEObjectType
                    InheritedObjectType = $ACEInheritedObjectType
                    Subject = $ACESubject
                }
            }
        }
    }
    
    return $ACLEntries
}

function Resolve-SIDToName {
    param(
        [string]$SID,
        [string]$DC = $null,
        [System.Management.Automation.PSCredential]$Cred = $null
    )
    
    try {
        $Filter = "(objectSid=$SID)"
        $DomainDN = Get-DomainDN -Domain $Domain
        $Object = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("sAMAccountName", "name", "distinguishedName") -DC $DC -Cred $Cred
        
        if ($Object -and $Object.Count -gt 0) {
            return $Object[0]
        }
    } catch {
        # Try SID string format
        try {
            $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
            return $SIDObj.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $SID
        }
    }
    
    return $SID
}

#endregion

#region Group Membership Resolution (For ACL Traversal)

$Script:GroupMembershipCache = @{}
$Script:UserGroupsCache = @{}

function Resolve-GroupMembership {
    param(
        [string]$GroupDN,
        [string]$DC = $null,
        [System.Management.Automation.PSCredential]$Cred = $null,
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0,
        [hashtable]$Visited = @{}
    )
    
    if ($CurrentDepth -gt $MaxDepth -or $Visited.ContainsKey($GroupDN)) {
        return @()
    }
    
    $Visited[$GroupDN] = $true
    
    if ($Script:GroupMembershipCache.ContainsKey($GroupDN)) {
        return $Script:GroupMembershipCache[$GroupDN]
    }
    
    $AllMembers = @()
    
    try {
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(distinguishedName=$($GroupDN -replace '\(', '\28' -replace '\)', '\29'))"
        
        $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("member", "objectClass") -DC $DC -Cred $Cred
        
        if ($Group -and $Group.Count -gt 0) {
            $Members = $Group[0].member
            if (-not $Members) { $Members = @() }
            if ($Members -isnot [array]) { $Members = @($Members) }
            
            foreach ($MemberDN in $Members) {
                if ($MemberDN) {
                    $AllMembers += $MemberDN
                    
                    # Check if member is a group (recursive)
                    $MemberFilter = "(distinguishedName=$($MemberDN -replace '\(', '\28' -replace '\)', '\29'))"
                    $MemberObject = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $MemberFilter -Properties @("objectClass") -DC $DC -Cred $Cred
                    
                    if ($MemberObject -and $MemberObject[0].objectClass -contains "group") {
                        $NestedMembers = Resolve-GroupMembership -GroupDN $MemberDN -DC $DC -Cred $Cred -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -Visited $Visited
                        $AllMembers += $NestedMembers
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error resolving group membership for $GroupDN : $_"
    }
    
    $AllMembers = $AllMembers | Select-Object -Unique
    $Script:GroupMembershipCache[$GroupDN] = $AllMembers
    return $AllMembers
}

function Resolve-UserGroups {
    param(
        [string]$UserDN,
        [string]$DC = $null,
        [System.Management.Automation.PSCredential]$Cred = $null
    )
    
    if ($Script:UserGroupsCache.ContainsKey($UserDN)) {
        return $Script:UserGroupsCache[$UserDN]
    }
    
    $AllGroups = @()
    $ProcessedGroups = @{}
    
    function Resolve-Recursive {
        param([string]$DN, [int]$Depth = 0)
        
        if ($Depth -gt 10 -or $ProcessedGroups.ContainsKey($DN)) {
            return
        }
        
        $ProcessedGroups[$DN] = $true
        
        try {
            $DomainDN = Get-DomainDN -Domain $Domain
            $Filter = "(distinguishedName=$($DN -replace '\(', '\28' -replace '\)', '\29'))"
            $Object = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("memberOf", "objectClass") -DC $DC -Cred $Cred
            
            if ($Object -and $Object.Count -gt 0) {
                $MemberOf = $Object[0].memberOf
                if ($MemberOf) {
                    if ($MemberOf -isnot [array]) { $MemberOf = @($MemberOf) }
                    
                    foreach ($GroupDN in $MemberOf) {
                        if ($GroupDN) {
                            $AllGroups += $GroupDN
                            Resolve-Recursive -DN $GroupDN -Depth ($Depth + 1)
                        }
                    }
                }
            }
        } catch {
            # Skip on error
        }
    }
    
    Resolve-Recursive -DN $UserDN
    $AllGroups = $AllGroups | Select-Object -Unique
    $Script:UserGroupsCache[$UserDN] = $AllGroups
    return $AllGroups
}

#endregion

#region ACL Traversal and Path Analysis

function Find-ACLAbusePaths {
    param(
        [string]$DC = $null,
        [System.Management.Automation.PSCredential]$Cred = $null
    )
    
    Write-SectionHeader "ACL ABUSE PATH ANALYSIS (BLOODHOUND-STYLE)"
    
    $Findings = @()
    $AbusePaths = @()
    
    try {
        Write-ColorOutput "  [*] Building group membership map..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Get all users
        $UserFilter = "(&(objectClass=user)(objectCategory=person))"
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $UserFilter -Properties @("distinguishedName", "sAMAccountName", "memberOf") -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Users.Count) users" -Color Green
        
        # Get all groups
        $GroupFilter = "(objectClass=group)"
        $Groups = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $GroupFilter -Properties @("distinguishedName", "sAMAccountName", "member", "memberOf") -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Groups.Count) groups" -Color Green
        
        # Build user -> groups map
        Write-ColorOutput "  [*] Resolving user group memberships..." -Color Cyan
        $UserGroupsMap = @{}
        
        foreach ($User in $Users) {
            $UserDN = $User.distinguishedName
            $UserGroups = Resolve-UserGroups -UserDN $UserDN -DC $DC -Cred $Cred
            $UserGroupsMap[$UserDN] = $UserGroups
        }
        
        # Check critical objects for dangerous ACLs
        Write-ColorOutput "  [*] Analyzing ACLs on critical objects..." -Color Cyan
        
        $CriticalObjects = @(
            @{DN = $DomainDN; Name = "Domain Root"; Type = "domainDNS"},
            @{DN = "CN=AdminSDHolder,CN=System,$DomainDN"; Name = "AdminSDHolder"; Type = "container"},
            @{DN = "OU=Domain Controllers,$DomainDN"; Name = "Domain Controllers OU"; Type = "organizationalUnit"}
        )
        
        # Dangerous rights to look for
        $DangerousRights = @{
            "GA" = "GenericAll"
            "GW" = "GenericWrite"
            "WD" = "WriteDacl"
            "WO" = "WriteOwner"
            "DC" = "DS-Replication-Get-Changes"
            "CA" = "DS-Replication-Get-Changes-All"
        }
        
        foreach ($CriticalObj in $CriticalObjects) {
            try {
                $Filter = "(distinguishedName=$($CriticalObj.DN -replace '\(', '\28' -replace '\)', '\29'))"
                $Object = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("nTSecurityDescriptor", "distinguishedName") -DC $DC -Cred $Cred
                
                if ($Object -and $Object.Count -gt 0 -and $Object[0].nTSecurityDescriptor) {
                    $SD = $Object[0].nTSecurityDescriptor
                    
                    # Convert binary SD to SDDL
                    try {
                        $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $SDObj.SetSecurityDescriptorBinaryForm($SD)
                        $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                        
                        # Parse SDDL
                        $ACLEntries = Parse-SDDL -SDDL $SDDL
                        
                        foreach ($ACE in $ACLEntries) {
                            if ($ACE.Type -eq "A" -and $DangerousRights.ContainsKey($ACE.Rights)) {
                                $RightName = $DangerousRights[$ACE.Rights]
                                $SubjectSID = $ACE.Subject
                                
                                # Resolve SID to name
                                $SubjectName = Resolve-SIDToName -SID $SubjectSID -DC $DC -Cred $Cred
                                
                                # Check if it's a user or group
                                $SubjectDN = $null
                                if ($SubjectName -is [hashtable]) {
                                    $SubjectDN = $SubjectName.distinguishedName
                                } else {
                                    # Try to find by SID
                                    $SubjectFilter = "(objectSid=$SubjectSID)"
                                    $SubjectObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $SubjectFilter -Properties @("distinguishedName", "objectClass", "sAMAccountName") -DC $DC -Cred $Cred
                                    if ($SubjectObj -and $SubjectObj.Count -gt 0) {
                                        $SubjectDN = $SubjectObj[0].distinguishedName
                                        $SubjectName = $SubjectObj[0].sAMAccountName
                                    }
                                }
                                
                                if ($SubjectDN) {
                                    # Check if it's a group - if so, find all members
                                    $SubjectFilter = "(distinguishedName=$($SubjectDN -replace '\(', '\28' -replace '\)', '\29'))"
                                    $SubjectObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $SubjectFilter -Properties @("objectClass") -DC $DC -Cred $Cred
                                    
                                    if ($SubjectObj -and $SubjectObj[0].objectClass -contains "group") {
                                        # It's a group - find all members (recursive)
                                        $GroupMembers = Resolve-GroupMembership -GroupDN $SubjectDN -DC $DC -Cred $Cred
                                        
                                        foreach ($MemberDN in $GroupMembers) {
                                            # Check if member is a user
                                            $MemberFilter = "(distinguishedName=$($MemberDN -replace '\(', '\28' -replace '\)', '\29'))"
                                            $MemberObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $MemberFilter -Properties @("objectClass", "sAMAccountName", "memberOf") -DC $DC -Cred $Cred
                                            
                                            if ($MemberObj -and $MemberObj[0].objectClass -contains "user") {
                                                $MemberName = $MemberObj[0].sAMAccountName
                                                
                                                # Build path: check if user is directly in group or through nested groups
                                                $UserGroups = Resolve-UserGroups -UserDN $MemberDN -DC $DC -Cred $Cred
                                                
                                                # Find the path chain
                                                $PathChain = @()
                                                $PathChain += $MemberName
                                                
                                                # Check if user is directly in the group
                                                if ($UserGroups -contains $SubjectDN) {
                                                    $PathChain += " -> Member of -> $SubjectName"
                                                } else {
                                                    # Find intermediate groups
                                                    foreach ($UserGroupDN in $UserGroups) {
                                                        $IntermediateGroupMembers = Resolve-GroupMembership -GroupDN $SubjectDN -DC $DC -Cred $Cred
                                                        if ($IntermediateGroupMembers -contains $UserGroupDN) {
                                                            $IntermediateGroupFilter = "(distinguishedName=$($UserGroupDN -replace '\(', '\28' -replace '\)', '\29'))"
                                                            $IntermediateGroupObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $IntermediateGroupFilter -Properties @("sAMAccountName") -DC $DC -Cred $Cred
                                                            if ($IntermediateGroupObj -and $IntermediateGroupObj.Count -gt 0) {
                                                                $IntermediateGroupName = $IntermediateGroupObj[0].sAMAccountName
                                                                $PathChain += " -> Member of -> $IntermediateGroupName -> Member of -> $SubjectName"
                                                                break
                                                            }
                                                        }
                                                    }
                                                }
                                                
                                                $Path = ($PathChain -join "") + " -> has $RightName on $($CriticalObj.Name)"
                                                
                                                $AbusePaths += @{
                                                    User = $MemberName
                                                    Path = $Path
                                                    Target = $CriticalObj.Name
                                                    Right = $RightName
                                                    Severity = if ($RightName -eq "GenericAll" -or $RightName -eq "DS-Replication-Get-Changes-All") { "CRITICAL" } else { "HIGH" }
                                                }
                                            }
                                        }
                                    } else {
                                        # It's a user directly
                                        $UserFilter = "(distinguishedName=$($SubjectDN -replace '\(', '\28' -replace '\)', '\29'))"
                                        $UserObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $UserFilter -Properties @("sAMAccountName") -DC $DC -Cred $Cred
                                        
                                        if ($UserObj -and $UserObj.Count -gt 0) {
                                            $UserName = $UserObj[0].sAMAccountName
                                            $Path = "$UserName -> has $RightName on $($CriticalObj.Name)"
                                            
                                            $AbusePaths += @{
                                                User = $UserName
                                                Path = $Path
                                                Target = $CriticalObj.Name
                                                Right = $RightName
                                                Severity = if ($RightName -eq "GenericAll" -or $RightName -eq "DS-Replication-Get-Changes-All") { "CRITICAL" } else { "HIGH" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Error parsing security descriptor for $($CriticalObj.Name): $_"
                    }
                }
            } catch {
                Write-Warning "Error accessing $($CriticalObj.Name): $_"
            }
        }
        
        # Group findings by severity
        $CriticalPaths = $AbusePaths | Where-Object { $_.Severity -eq "CRITICAL" }
        $HighPaths = $AbusePaths | Where-Object { $_.Severity -eq "HIGH" }
        
        if ($CriticalPaths.Count -gt 0) {
            $Findings += @{
                Title = "CRITICAL ACL Abuse Paths Detected"
                Severity = "CRITICAL"
                Description = "$($CriticalPaths.Count) users have CRITICAL rights on sensitive objects through group membership"
                Details = ($CriticalPaths | Select-Object -First 20 | ForEach-Object { $_.Path })
            }
        }
        
        if ($HighPaths.Count -gt 0) {
            $Findings += @{
                Title = "HIGH ACL Abuse Paths Detected"
                Severity = "HIGH"
                Description = "$($HighPaths.Count) users have HIGH-risk rights on sensitive objects through group membership"
                Details = ($HighPaths | Select-Object -First 20 | ForEach-Object { $_.Path })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        if ($AbusePaths.Count -eq 0) {
            Write-ColorOutput "  [+] No ACL abuse paths detected on critical objects" -Color Green
        } else {
            Write-ColorOutput "  [*] Total ACL abuse paths found: $($AbusePaths.Count)" -Color Yellow
        }
        
        return @{
            AbusePaths = $AbusePaths
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing ACL paths: $_" -Color Red
        return $null
    }
}

#endregion

#region Domain Information (LDAP)

function Get-DomainAuditInfo {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DOMAIN INFORMATION"
    
    try {
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=domainDNS)"
        
        $Properties = @("distinguishedName", "name", "dc", "domainFunctionality", "forestFunctionality", "objectSid")
        $DomainInfo = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($DomainInfo -and $DomainInfo.Count -gt 0) {
            $Info = $DomainInfo[0]
            
            Write-ColorOutput "  Domain Name: " -Color Cyan -NoNewline
            Write-ColorOutput $Domain -Color White
            
            Write-ColorOutput "  Distinguished Name: " -Color Cyan -NoNewline
            Write-ColorOutput $Info.distinguishedName -Color White
            
            if ($Info.name) {
                Write-ColorOutput "  NetBIOS Name: " -Color Cyan -NoNewline
                Write-ColorOutput $Info.name -Color White
            }
            
            if ($Info.domainFunctionality) {
                Write-ColorOutput "  Domain Functionality: " -Color Cyan -NoNewline
                Write-ColorOutput $Info.domainFunctionality -Color White
            }
            
            if ($Info.forestFunctionality) {
                Write-ColorOutput "  Forest Functionality: " -Color Cyan -NoNewline
                Write-ColorOutput $Info.forestFunctionality -Color White
            }
            
            if ($Info.objectSid) {
                Write-ColorOutput "  Domain SID: " -Color Cyan -NoNewline
                try {
                    $SID = New-Object System.Security.Principal.SecurityIdentifier($Info.objectSid, 0)
                    Write-ColorOutput $SID.Value -Color White
                } catch {
                    Write-ColorOutput "N/A" -Color Gray
                }
            }
        }
        
        return $DomainInfo
        
    } catch {
        Write-ColorOutput "  [!] Could not retrieve domain information: $_" -Color Red
        return $null
    }
}

#endregion

#region User Enumeration (LDAP) - Comprehensive

function Get-UserAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "USER ENUMERATION AND ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating all users via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(objectClass=user)(objectCategory=person))"
        
        $Properties = @(
            "distinguishedName", "sAMAccountName", "userPrincipalName", "name", "displayName",
            "userAccountControl", "pwdLastSet", "accountExpires", "lastLogon", "lastLogonTimestamp",
            "memberOf", "servicePrincipalName", "description", "comment", "info", "adminCount",
            "userPassword", "unicodePwd", "msDS-UserPasswordExpiryTimeComputed", "whenCreated",
            "whenChanged", "badPwdCount", "lockoutTime", "logonCount"
        )
        
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Users.Count) users" -Color Green
        Write-Host ""
        
        # Analyze users
        $PasswordNeverExpires = @()
        $PasswordNotRequired = @()
        $NoPreAuth = @()
        $ServiceAccounts = @()
        $NeverLoggedOn = @()
        $OldPasswords = @()
        $SuspiciousDescriptions = @()
        $PasswordAge5Years = @()
        $PasswordAge2Years = @()
        $PasswordAge1Year = @()
        $PasswordAge6Months = @()
        $PasswordNeverSet = @()
        
        foreach ($User in $Users) {
            $UAC = if ($User.userAccountControl) { [int]$User.userAccountControl } else { 0 }
            $Enabled = ($UAC -band 0x0002) -eq 0
            
            if (-not $Enabled) { continue }
            
            # Password never expires (0x10000)
            if (($UAC -band 0x10000) -ne 0) {
                $PasswordNeverExpires += $User
            }
            
            # Password not required (0x0020)
            if (($UAC -band 0x0020) -ne 0) {
                $PasswordNotRequired += $User
            }
            
            # No pre-auth (0x400000)
            if (($UAC -band 0x400000) -ne 0) {
                $NoPreAuth += $User
            }
            
            # Service accounts (has SPN)
            if ($User.servicePrincipalName) {
                $ServiceAccounts += $User
            }
            
            # Never logged on
            if (-not $User.lastLogon -and -not $User.lastLogonTimestamp) {
                $NeverLoggedOn += $User
            }
            
            # Password age analysis
            if ($User.pwdLastSet) {
                try {
                    $PwdLastSet = [DateTime]::FromFileTime([int64]$User.pwdLastSet)
                    $DaysSince = (New-TimeSpan -Start $PwdLastSet -End (Get-Date)).Days
                    
                    if ($DaysSince -gt 1825) { # 5 years
                        $PasswordAge5Years += $User
                    } elseif ($DaysSince -gt 730) { # 2 years
                        $PasswordAge2Years += $User
                    } elseif ($DaysSince -gt 365) { # 1 year
                        $PasswordAge1Year += $User
                    } elseif ($DaysSince -gt 180) { # 6 months
                        $PasswordAge6Months += $User
                    }
                } catch {
                    # Skip if can't parse
                }
            } else {
                $PasswordNeverSet += $User
            }
            
            # Suspicious descriptions
            $SuspiciousKeywords = @("password", "pass", "pwd", "secret", "key", "credential", "login", "admin", "root")
            if ($User.description) {
                $DescLower = $User.description.ToString().ToLower()
                foreach ($Keyword in $SuspiciousKeywords) {
                    if ($DescLower -like "*$Keyword*") {
                        $SuspiciousDescriptions += $User
                        break
                    }
                }
            }
            
            # Check comment, info fields
            foreach ($Field in @("comment", "info")) {
                if ($User.$Field) {
                    $FieldLower = $User.$Field.ToString().ToLower()
                    foreach ($Keyword in $SuspiciousKeywords) {
                        if ($FieldLower -like "*$Keyword*") {
                            $SuspiciousDescriptions += $User
                            break
                        }
                    }
                }
            }
        }
        
        # Findings
        Write-ColorOutput "  [*] Analyzing user security issues..." -Color Cyan
        Write-Host ""
        
        if ($PasswordNotRequired.Count -gt 0) {
            $Findings += @{
                Title = "Users with Password Not Required"
                Severity = "CRITICAL"
                Description = "$($PasswordNotRequired.Count) users do not require passwords"
                Details = ($PasswordNotRequired | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($PasswordNeverExpires.Count -gt 0) {
            $Findings += @{
                Title = "Users with Password Never Expires"
                Severity = "HIGH"
                Description = "$($PasswordNeverExpires.Count) users have passwords that never expire"
                Details = ($PasswordNeverExpires | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($NoPreAuth.Count -gt 0) {
            $Findings += @{
                Title = "Users Vulnerable to AS-REP Roasting"
                Severity = "HIGH"
                Description = "$($NoPreAuth.Count) users do not require Kerberos pre-authentication"
                Details = ($NoPreAuth | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($ServiceAccounts.Count -gt 0) {
            $Findings += @{
                Title = "Service Accounts (Kerberoastable)"
                Severity = "MEDIUM"
                Description = "$($ServiceAccounts.Count) users have Service Principal Names (SPNs)"
                Details = ($ServiceAccounts | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($SuspiciousDescriptions.Count -gt 0) {
            $Findings += @{
                Title = "Users with Suspicious Content in Description/Comments/Info"
                Severity = "HIGH"
                Description = "$($SuspiciousDescriptions.Count) users have suspicious keywords in description/comment/info fields"
                Details = ($SuspiciousDescriptions | Select-Object -First 20 | ForEach-Object { 
                    "$($_.sAMAccountName): $($_.description)" 
                })
            }
        }
        
        if ($PasswordAge5Years.Count -gt 0) {
            $Findings += @{
                Title = "Users with Passwords Older Than 5 Years"
                Severity = "HIGH"
                Description = "$($PasswordAge5Years.Count) users have passwords that haven't been changed in 5+ years"
                Details = ($PasswordAge5Years | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($PasswordAge2Years.Count -gt 0) {
            $Findings += @{
                Title = "Users with Passwords Older Than 2 Years"
                Severity = "HIGH"
                Description = "$($PasswordAge2Years.Count) users have passwords that haven't been changed in 2+ years"
                Details = ($PasswordAge2Years | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($PasswordAge1Year.Count -gt 0) {
            $Findings += @{
                Title = "Users with Passwords Older Than 1 Year"
                Severity = "MEDIUM"
                Description = "$($PasswordAge1Year.Count) users have passwords that haven't been changed in 1+ year"
                Details = ($PasswordAge1Year | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($PasswordNeverSet.Count -gt 0) {
            $Findings += @{
                Title = "Users with Passwords Never Set"
                Severity = "HIGH"
                Description = "$($PasswordNeverSet.Count) users have never set a password"
                Details = ($PasswordNeverSet | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        # Statistics
        Write-ColorOutput "  [*] User Statistics:" -Color Cyan
        Write-ColorOutput "      Total Users: $($Users.Count)" -Color Gray
        Write-ColorOutput "      Password Never Expires: $($PasswordNeverExpires.Count)" -Color Gray
        Write-ColorOutput "      Password Not Required: $($PasswordNotRequired.Count)" -Color Yellow
        Write-ColorOutput "      AS-REP Roastable: $($NoPreAuth.Count)" -Color Yellow
        Write-ColorOutput "      Service Accounts: $($ServiceAccounts.Count)" -Color Gray
        Write-ColorOutput "      Passwords >5 years: $($PasswordAge5Years.Count)" -Color Yellow
        Write-ColorOutput "      Passwords >2 years: $($PasswordAge2Years.Count)" -Color Yellow
        Write-ColorOutput "      Passwords >1 year: $($PasswordAge1Year.Count)" -Color Gray
        
        return @{
            Users = $Users
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating users: $_" -Color Red
        return $null
    }
}

#endregion

#region Group Enumeration (LDAP)

function Get-GroupAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "GROUP ENUMERATION AND ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating all groups via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=group)"
        
        $Properties = @("distinguishedName", "sAMAccountName", "name", "member", "memberOf", "groupType", "adminCount")
        $Groups = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Groups.Count) groups" -Color Green
        Write-Host ""
        
        # Critical groups
        $CriticalGroupNames = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators", "Server Operators", "Print Operators")
        $CriticalGroups = @()
        
        foreach ($Group in $Groups) {
            $GroupName = $Group.sAMAccountName
            if ($CriticalGroupNames -contains $GroupName) {
                $CriticalGroups += $Group
                
                # Get members recursively
                $Members = Resolve-GroupMembership -GroupDN $Group.distinguishedName -DC $DC -Cred $Cred
                
                if ($Members.Count -gt 0) {
                    Write-ColorOutput "  [*] $GroupName : $($Members.Count) members" -Color Yellow
                    
                    $Findings += @{
                        Title = "Members of $GroupName"
                        Severity = "CRITICAL"
                        Description = "$GroupName has $($Members.Count) members (privileged group)"
                        Details = ($Members | Select-Object -First 10)
                    }
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Groups = $Groups
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating groups: $_" -Color Red
        return $null
    }
}

#endregion

#region Computer Enumeration (LDAP)

function Get-ComputerAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "COMPUTER ENUMERATION AND ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating all computers via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=computer)"
        
        $Properties = @("distinguishedName", "name", "dNSHostName", "userAccountControl", "operatingSystem", "operatingSystemVersion", "pwdLastSet", "lastLogon", "lastLogonTimestamp", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity")
        $Computers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Computers.Count) computers" -Color Green
        Write-Host ""
        
        $UnconstrainedDelegation = @()
        $ConstrainedDelegation = @()
        $RBCD = @()
        
        foreach ($Computer in $Computers) {
            $UAC = if ($Computer.userAccountControl) { [int]$Computer.userAccountControl } else { 0 }
            
            # Unconstrained delegation (0x80000)
            if (($UAC -band 0x80000) -ne 0) {
                $UnconstrainedDelegation += $Computer
            }
            
            # Constrained delegation
            if ($Computer.'msDS-AllowedToDelegateTo') {
                $ConstrainedDelegation += $Computer
            }
            
            # RBCD
            if ($Computer.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $RBCD += $Computer
            }
        }
        
        if ($UnconstrainedDelegation.Count -gt 0) {
            $Findings += @{
                Title = "Computers with Unconstrained Delegation"
                Severity = "HIGH"
                Description = "$($UnconstrainedDelegation.Count) computers have unconstrained delegation enabled"
                Details = ($UnconstrainedDelegation | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        if ($ConstrainedDelegation.Count -gt 0) {
            $Findings += @{
                Title = "Computers with Constrained Delegation"
                Severity = "MEDIUM"
                Description = "$($ConstrainedDelegation.Count) computers have constrained delegation configured"
                Details = ($ConstrainedDelegation | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        if ($RBCD.Count -gt 0) {
            $Findings += @{
                Title = "Computers with Resource-Based Constrained Delegation"
                Severity = "MEDIUM"
                Description = "$($RBCD.Count) computers have RBCD configured"
                Details = ($RBCD | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Computers = $Computers
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating computers: $_" -Color Red
        return $null
    }
}

#endregion

#region Password Policy (LDAP)

function Get-PasswordPolicyAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "PASSWORD POLICY ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing domain password policy via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=domainDNS)"
        
        $Properties = @("minPwdLength", "pwdHistoryLength", "pwdProperties", "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow")
        $DomainInfo = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($DomainInfo -and $DomainInfo.Count -gt 0) {
            $Policy = $DomainInfo[0]
            
            Write-ColorOutput "  [+] Password Policy Settings:" -Color Green
            
            if ($Policy.minPwdLength) {
                $MinLength = [int]$Policy.minPwdLength
                Write-ColorOutput "      MinPasswordLength: $MinLength" -Color Gray
                
                if ($MinLength -lt 14) {
                    $Findings += @{
                        Title = "Weak Minimum Password Length"
                        Severity = "HIGH"
                        Description = "Minimum password length is $MinLength (recommended: 14+)"
                        Details = "Current: $MinLength"
                    }
                }
            }
            
            if ($Policy.pwdProperties) {
                $PwdProps = [int]$Policy.pwdProperties
                # Reversible encryption (0x00000004)
                if (($PwdProps -band 0x00000004) -ne 0) {
                    $Findings += @{
                        Title = "Reversible Encryption Enabled"
                        Severity = "CRITICAL"
                        Description = "Password reversible encryption is enabled (passwords stored in plaintext-equivalent)"
                        Details = "This is a critical security risk"
                    }
                }
                
                # Complexity disabled (0x00000001 means complexity is DISABLED)
                if (($PwdProps -band 0x00000001) -eq 0) {
                    # Complexity is enabled (good)
                } else {
                    $Findings += @{
                        Title = "Password Complexity Disabled"
                        Severity = "HIGH"
                        Description = "Password complexity requirements are disabled"
                        Details = "Passwords do not require complexity"
                    }
                }
            }
            
            if ($Policy.lockoutThreshold) {
                $Threshold = [int]$Policy.lockoutThreshold
                Write-ColorOutput "      LockoutThreshold: $Threshold" -Color Gray
                
                if ($Threshold -eq 0) {
                    $Findings += @{
                        Title = "Account Lockout Disabled"
                        Severity = "HIGH"
                        Description = "Account lockout is disabled (no brute force protection)"
                        Details = "LockoutThreshold is 0"
                    }
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Policy = $DomainInfo
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing password policy: $_" -Color Red
        return $null
    }
}

#endregion

#region Trust Analysis (LDAP)

function Get-TrustAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DOMAIN TRUST ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating domain trusts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=trustedDomain)"
        
        $Properties = @("name", "trustDirection", "trustType", "trustAttributes", "flatName")
        $Trusts = Invoke-LDAPQuery -SearchBase "CN=System,$DomainDN" -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($Trusts) {
            Write-ColorOutput "  [+] Found $($Trusts.Count) trusts" -Color Green
            Write-Host ""
            
            foreach ($Trust in $Trusts) {
                Write-ColorOutput "  [*] Trust: $($Trust.name)" -Color Cyan
                
                if ($Trust.trustDirection) {
                    $Direction = [int]$Trust.trustDirection
                    $DirectionText = switch ($Direction) {
                        0 { "Disabled" }
                        1 { "Inbound" }
                        2 { "Outbound" }
                        3 { "Bidirectional" }
                        default { "Unknown" }
                    }
                    Write-ColorOutput "      Direction: $DirectionText" -Color Gray
                }
                
                # Check SID filtering (trustAttributes)
                if ($Trust.trustAttributes) {
                    $TrustAttrs = [int]$Trust.trustAttributes
                    # 0x00000004 = TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (SID filtering enabled)
                    if (($TrustAttrs -band 0x00000004) -eq 0) {
                        $Findings += @{
                            Title = "SID Filtering Disabled on Trust"
                            Severity = "HIGH"
                            Description = "Trust $($Trust.name) has SID filtering disabled"
                            Details = "This allows SID history attacks across trusts"
                        }
                    }
                }
                
                Write-Host ""
            }
        } else {
            Write-ColorOutput "  [+] No trusts found" -Color Green
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Trusts = $Trusts
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating trusts: $_" -Color Red
        return $null
    }
}

#endregion

#region Delegation Analysis (LDAP)

function Get-DelegationAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DELEGATION ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing delegation configurations via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Unconstrained delegation (users)
        $UserFilter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        $UnconstrainedUsers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $UserFilter -Properties @("distinguishedName", "sAMAccountName") -DC $DC -Cred $Cred
        
        # Constrained delegation (users)
        $ConstrainedUserFilter = "(&(objectClass=user)(msDS-AllowedToDelegateTo=*))"
        $ConstrainedUsers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $ConstrainedUserFilter -Properties @("distinguishedName", "sAMAccountName", "msDS-AllowedToDelegateTo") -DC $DC -Cred $Cred
        
        # RBCD
        $RBCDFilter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        $RBCDObjects = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $RBCDFilter -Properties @("distinguishedName", "name", "msDS-AllowedToActOnBehalfOfOtherIdentity") -DC $DC -Cred $Cred
        
        if ($UnconstrainedUsers.Count -gt 0) {
            $Findings += @{
                Title = "Users with Unconstrained Delegation"
                Severity = "HIGH"
                Description = "$($UnconstrainedUsers.Count) users have unconstrained delegation enabled"
                Details = ($UnconstrainedUsers | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($ConstrainedUsers.Count -gt 0) {
            $Findings += @{
                Title = "Users with Constrained Delegation"
                Severity = "MEDIUM"
                Description = "$($ConstrainedUsers.Count) users have constrained delegation configured"
                Details = ($ConstrainedUsers | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($RBCDObjects.Count -gt 0) {
            $Findings += @{
                Title = "Objects with Resource-Based Constrained Delegation"
                Severity = "MEDIUM"
                Description = "$($RBCDObjects.Count) objects have RBCD configured"
                Details = ($RBCDObjects | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            UnconstrainedUsers = $UnconstrainedUsers
            ConstrainedUsers = $ConstrainedUsers
            RBCDObjects = $RBCDObjects
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing delegation: $_" -Color Red
        return $null
    }
}

#endregion

#region Kerberoastable Detection (LDAP)

function Get-KerberoastableAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "KERBEROASTABLE ACCOUNTS DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting kerberoastable accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(servicePrincipalName=*)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "servicePrincipalName", "userAccountControl", "memberOf")
        $Kerberoastable = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($Kerberoastable.Count) kerberoastable accounts" -Color Green
        Write-Host ""
        
        # Check for admin group members
        $InAdminGroups = @()
        foreach ($Account in $Kerberoastable) {
            if ($Account.memberOf) {
                $MemberOf = if ($Account.memberOf -is [array]) { $Account.memberOf } else { @($Account.memberOf) }
                foreach ($GroupDN in $MemberOf) {
                    if ($GroupDN -like "*Domain Admins*" -or $GroupDN -like "*Enterprise Admins*") {
                        $InAdminGroups += $Account
                        break
                    }
                }
            }
        }
        
        if ($Kerberoastable.Count -gt 0) {
            $Findings += @{
                Title = "Kerberoastable Accounts Detected"
                Severity = "MEDIUM"
                Description = "$($Kerberoastable.Count) accounts have Service Principal Names and can be kerberoasted"
                Details = ($Kerberoastable | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($InAdminGroups.Count -gt 0) {
            $Findings += @{
                Title = "Kerberoastable Accounts in Admin Groups"
                Severity = "CRITICAL"
                Description = "$($InAdminGroups.Count) kerberoastable accounts are members of admin groups"
                Details = ($InAdminGroups | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Kerberoastable = $Kerberoastable
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting kerberoastable accounts: $_" -Color Red
        return $null
    }
}

#endregion

#region AS-REP Roastable Detection (LDAP)

function Get-ASREPRoastableAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "AS-REP ROASTABLE ACCOUNTS DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting AS-REP roastable accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "userAccountControl", "memberOf", "servicePrincipalName")
        $ASREPRoastable = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($ASREPRoastable.Count) AS-REP roastable accounts" -Color Green
        Write-Host ""
        
        # Check for admin group members
        $InAdminGroups = @()
        $AlsoKerberoastable = @()
        
        foreach ($Account in $ASREPRoastable) {
            if ($Account.memberOf) {
                $MemberOf = if ($Account.memberOf -is [array]) { $Account.memberOf } else { @($Account.memberOf) }
                foreach ($GroupDN in $MemberOf) {
                    if ($GroupDN -like "*Domain Admins*" -or $GroupDN -like "*Enterprise Admins*") {
                        $InAdminGroups += $Account
                        break
                    }
                }
            }
            
            if ($Account.servicePrincipalName) {
                $AlsoKerberoastable += $Account
            }
        }
        
        if ($ASREPRoastable.Count -gt 0) {
            $Findings += @{
                Title = "AS-REP Roastable Accounts Detected"
                Severity = "HIGH"
                Description = "$($ASREPRoastable.Count) accounts do not require Kerberos pre-authentication and can be AS-REP roasted"
                Details = ($ASREPRoastable | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($InAdminGroups.Count -gt 0) {
            $Findings += @{
                Title = "AS-REP Roastable Accounts in Admin Groups"
                Severity = "CRITICAL"
                Description = "$($InAdminGroups.Count) AS-REP roastable accounts are members of admin groups"
                Details = ($InAdminGroups | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($AlsoKerberoastable.Count -gt 0) {
            $Findings += @{
                Title = "AS-REP Roastable Accounts Also Kerberoastable"
                Severity = "CRITICAL"
                Description = "$($AlsoKerberoastable.Count) accounts are both AS-REP roastable and kerberoastable"
                Details = ($AlsoKerberoastable | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            ASREPRoastable = $ASREPRoastable
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting AS-REP roastable accounts: $_" -Color Red
        return $null
    }
}

#endregion

#region Shadow Admins Detection (LDAP)

function Get-ShadowAdminsAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SHADOW ADMINS DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting shadow admins via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "adminCount", "memberOf")
        $AdminCountUsers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        # Get admin group DNs
        $AdminGroupDNs = @()
        $AdminGroupNames = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators", "Print Operators")
        
        foreach ($GroupName in $AdminGroupNames) {
            $GroupFilter = "(sAMAccountName=$GroupName)"
            $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $GroupFilter -Properties @("distinguishedName") -DC $DC -Cred $Cred
            if ($Group -and $Group.Count -gt 0) {
                $AdminGroupDNs += $Group[0].distinguishedName
            }
        }
        
        $ShadowAdmins = @()
        
        foreach ($User in $AdminCountUsers) {
            $IsInAdminGroup = $false
            if ($User.memberOf) {
                $MemberOf = if ($User.memberOf -is [array]) { $User.memberOf } else { @($User.memberOf) }
                foreach ($GroupDN in $MemberOf) {
                    if ($AdminGroupDNs -contains $GroupDN) {
                        $IsInAdminGroup = $true
                        break
                    }
                }
            }
            
            if (-not $IsInAdminGroup) {
                $ShadowAdmins += $User
            }
        }
        
        if ($ShadowAdmins.Count -gt 0) {
            $Findings += @{
                Title = "Shadow Admin Accounts Detected"
                Severity = "HIGH"
                Description = "$($ShadowAdmins.Count) users have AdminCount=1 but are not in standard admin groups (may have admin rights via ACLs)"
                Details = ($ShadowAdmins | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        if ($ShadowAdmins.Count -eq 0) {
            Write-ColorOutput "  [+] No shadow admins detected" -Color Green
        }
        
        return @{
            ShadowAdmins = $ShadowAdmins
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting shadow admins: $_" -Color Red
        return $null
    }
}

#endregion

#region Additional Audit Functions (LDAP-based)

function Get-UserAttributeAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "USER ATTRIBUTE ANALYSIS (DESCRIPTIONS, COMMENTS, ETC.)"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing user attributes for suspicious content via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(objectClass=user)(objectCategory=person))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "description", "comment", "info", "notes", "pwdLastSet", "userAccountControl", "memberOf", "lastLogonTimestamp")
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        $SuspiciousDescriptions = @()
        $PasswordKeywords = @("password", "pass", "pwd", "secret", "key", "credential", "login", "admin", "root")
        
        foreach ($User in $Users) {
            $UAC = if ($User.userAccountControl) { [int]$User.userAccountControl } else { 0 }
            $Enabled = ($UAC -band 0x0002) -eq 0
            if (-not $Enabled) { continue }
            
            foreach ($Field in @("description", "comment", "info", "notes")) {
                if ($User.$Field) {
                    $FieldLower = $User.$Field.ToString().ToLower()
                    foreach ($Keyword in $PasswordKeywords) {
                        if ($FieldLower -like "*$Keyword*") {
                            $SuspiciousDescriptions += @{
                                User = $User.sAMAccountName
                                Field = $Field
                                Content = $User.$Field
                            }
                            break
                        }
                    }
                }
            }
        }
        
        if ($SuspiciousDescriptions.Count -gt 0) {
            $Findings += @{
                Title = "Users with Suspicious Content in Description/Comments/Info/Notes"
                Severity = "HIGH"
                Description = "$($SuspiciousDescriptions.Count) users have suspicious keywords in their attributes"
                Details = ($SuspiciousDescriptions | Select-Object -First 20 | ForEach-Object { "$($_.User) ($($_.Field)): $($_.Content)" })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            SuspiciousDescriptions = $SuspiciousDescriptions
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing user attributes: $_" -Color Red
        return $null
    }
}

function Get-ServiceAccountAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SERVICE ACCOUNT ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing service accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(servicePrincipalName=*)(objectClass=user)(objectCategory=person))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "userAccountControl", "pwdLastSet", "memberOf", "servicePrincipalName")
        $ServiceAccounts = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($ServiceAccounts.Count) service accounts" -Color Green
        Write-Host ""
        
        $PasswordNeverExpires = @()
        $NoPreAuth = @()
        $OldPasswords = @()
        $InAdminGroups = @()
        
        foreach ($Account in $ServiceAccounts) {
            $UAC = if ($Account.userAccountControl) { [int]$Account.userAccountControl } else { 0 }
            $Enabled = ($UAC -band 0x0002) -eq 0
            if (-not $Enabled) { continue }
            
            if (($UAC -band 0x10000) -ne 0) {
                $PasswordNeverExpires += $Account
            }
            
            if (($UAC -band 0x400000) -ne 0) {
                $NoPreAuth += $Account
            }
            
            if ($Account.pwdLastSet) {
                try {
                    $PwdLastSet = [DateTime]::FromFileTime([int64]$Account.pwdLastSet)
                    $DaysSince = (New-TimeSpan -Start $PwdLastSet -End (Get-Date)).Days
                    if ($DaysSince -gt 365) {
                        $OldPasswords += $Account
                    }
                } catch { }
            }
            
            if ($Account.memberOf) {
                $MemberOf = if ($Account.memberOf -is [array]) { $Account.memberOf } else { @($Account.memberOf) }
                foreach ($GroupDN in $MemberOf) {
                    if ($GroupDN -like "*Domain Admins*" -or $GroupDN -like "*Enterprise Admins*") {
                        $InAdminGroups += $Account
                        break
                    }
                }
            }
        }
        
        if ($PasswordNeverExpires.Count -gt 0) {
            $Findings += @{
                Title = "Service Accounts with Password Never Expires"
                Severity = "HIGH"
                Description = "$($PasswordNeverExpires.Count) service accounts have passwords that never expire"
                Details = ($PasswordNeverExpires | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($InAdminGroups.Count -gt 0) {
            $Findings += @{
                Title = "Service Accounts in Admin Groups"
                Severity = "CRITICAL"
                Description = "$($InAdminGroups.Count) service accounts are members of admin groups"
                Details = ($InAdminGroups | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        if ($OldPasswords.Count -gt 0) {
            $Findings += @{
                Title = "Service Accounts with Old Passwords (>1 year)"
                Severity = "HIGH"
                Description = "$($OldPasswords.Count) service accounts have passwords older than 1 year"
                Details = ($OldPasswords | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            ServiceAccounts = $ServiceAccounts
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing service accounts: $_" -Color Red
        return $null
    }
}

function Get-GPOAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "GROUP POLICY OBJECT (GPO) ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating Group Policy Objects via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=groupPolicyContainer)"
        
        $Properties = @("distinguishedName", "name", "displayName", "gPCFileSysPath", "flags")
        $GPOs = Invoke-LDAPQuery -SearchBase "CN=Policies,CN=System,$DomainDN" -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($GPOs) {
            Write-ColorOutput "  [+] Found $($GPOs.Count) GPOs" -Color Green
            Write-Host ""
            
            # Check for disabled GPOs (flags attribute)
            $DisabledGPOs = @()
            foreach ($GPO in $GPOs) {
                if ($GPO.flags) {
                    $Flags = [int]$GPO.flags
                    # Flag 1 = GPO is disabled
                    if (($Flags -band 1) -ne 0) {
                        $DisabledGPOs += $GPO
                    }
                }
            }
            
            if ($DisabledGPOs.Count -gt 0) {
                $Findings += @{
                    Title = "Disabled GPOs"
                    Severity = "LOW"
                    Description = "$($DisabledGPOs.Count) GPOs are disabled"
                    Details = ($DisabledGPOs | Select-Object -First 20 | ForEach-Object { $_.displayName })
                }
            }
        } else {
            Write-ColorOutput "  [!] Could not enumerate GPOs" -Color Yellow
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            GPOs = $GPOs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating GPOs: $_" -Color Red
        return $null
    }
}

function Get-OUAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "ORGANIZATIONAL UNIT (OU) ANALYSIS"
    
    try {
        Write-ColorOutput "  [*] Enumerating Organizational Units via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=organizationalUnit)"
        
        $Properties = @("distinguishedName", "name", "description")
        $OUs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [+] Found $($OUs.Count) OUs" -Color Green
        Write-Host ""
        
        return @{
            OUs = $OUs
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating OUs: $_" -Color Red
        return $null
    }
}

function Get-ProtectedUsersAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "PROTECTED USERS ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Protected Users group via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(sAMAccountName=Protected Users)"
        
        $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "member") -DC $DC -Cred $Cred
        
        if ($Group -and $Group.Count -gt 0) {
            $Members = Resolve-GroupMembership -GroupDN $Group[0].distinguishedName -DC $DC -Cred $Cred
            Write-ColorOutput "  [+] Found $($Members.Count) members in Protected Users group" -Color Green
            Write-Host ""
        } else {
            Write-ColorOutput "  [!] Protected Users group not found or empty" -Color Yellow
        }
        
        return @{
            ProtectedUsers = $Members
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing Protected Users: $_" -Color Red
        return $null
    }
}

function Get-AdminSDHolderAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "AdminSDHolder ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing AdminSDHolder via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
        $Filter = "(distinguishedName=$($AdminSDHolderDN -replace '\(', '\28' -replace '\)', '\29'))"
        
        $AdminSDHolder = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "nTSecurityDescriptor") -DC $DC -Cred $Cred
        
        if ($AdminSDHolder -and $AdminSDHolder.Count -gt 0) {
            Write-ColorOutput "  [+] AdminSDHolder found" -Color Green
            Write-ColorOutput "      Distinguished Name: $($AdminSDHolder[0].distinguishedName)" -Color Gray
        } else {
            Write-ColorOutput "  [!] Could not access AdminSDHolder" -Color Yellow
        }
        
        return @{
            AdminSDHolder = $AdminSDHolder
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing AdminSDHolder: $_" -Color Red
        return $null
    }
}

function Get-ADCSAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "ACTIVE DIRECTORY CERTIFICATE SERVICES (ADCS) AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating ADCS configuration via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $CAFilter = "(&(objectCategory=pKIEnrollmentService)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        
        $CAs = Invoke-LDAPQuery -SearchBase "CN=Services,CN=Configuration,$DomainDN" -LDAPFilter $CAFilter -Properties @("distinguishedName", "name", "dNSHostName") -DC $DC -Cred $Cred
        
        if ($CAs) {
            Write-ColorOutput "  [+] Found $($CAs.Count) Certificate Authority servers" -Color Green
            Write-Host ""
        }
        
        # Certificate Templates
        $TemplateFilter = "(objectCategory=pKICertificateTemplate)"
        $Templates = Invoke-LDAPQuery -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" -LDAPFilter $TemplateFilter -Properties @("distinguishedName", "name", "pKIEnrollmentFlag", "pKIKeyUsage") -DC $DC -Cred $Cred
        
        if ($Templates) {
            Write-ColorOutput "  [+] Found $($Templates.Count) Certificate Templates" -Color Green
            Write-Host ""
        }
        
        return @{
            CAs = $CAs
            Templates = $Templates
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing ADCS: $_" -Color Red
        return $null
    }
}

function Get-GPPPasswordAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "GROUP POLICY PREFERENCE (GPP) PASSWORD DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Searching for GPP passwords via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=groupPolicyContainer)"
        
        $GPOs = Invoke-LDAPQuery -SearchBase "CN=Policies,CN=System,$DomainDN" -LDAPFilter $Filter -Properties @("distinguishedName", "name", "gPCFileSysPath") -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [*] Note: GPP password detection requires file system access to SYSVOL" -Color Yellow
        Write-ColorOutput "  [*] Use tools like Get-GPPPassword or manually check SYSVOL shares" -Color Yellow
        
        $Findings += @{
            Title = "GPP Password Detection"
            Severity = "INFO"
            Description = "Manual review required: Check SYSVOL shares for GPP XML files with cpassword attributes"
            Details = "Use Get-GPPPassword or search SYSVOL for *.xml files containing 'cpassword'"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing GPP passwords: $_" -Color Red
        return $null
    }
}

function Get-LAPSAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "LOCAL ADMINISTRATOR PASSWORD SOLUTION (LAPS) AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Checking for LAPS configuration via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(ms-Mcs-AdmPwd=*)"
        
        $LAPSComputers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "name", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime") -DC $DC -Cred $Cred
        
        if ($LAPSComputers) {
            Write-ColorOutput "  [+] Found $($LAPSComputers.Count) computers with LAPS passwords configured" -Color Green
            Write-Host ""
        } else {
            Write-ColorOutput "  [!] LAPS not detected or not configured" -Color Yellow
            $Findings += @{
                Title = "LAPS Not Installed"
                Severity = "MEDIUM"
                Description = "LAPS (Local Administrator Password Solution) is not installed"
                Details = "Consider implementing LAPS to manage local administrator passwords"
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            LAPSComputers = $LAPSComputers
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing LAPS: $_" -Color Red
        return $null
    }
}

function Get-gMSAAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "GROUP MANAGED SERVICE ACCOUNTS (gMSA) AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating Group Managed Service Accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectCategory=msDS-GroupManagedServiceAccount)"
        
        $gMSAs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "name", "msDS-GroupMSAMembership", "servicePrincipalName") -DC $DC -Cred $Cred
        
        if ($gMSAs) {
            Write-ColorOutput "  [+] Found $($gMSAs.Count) Group Managed Service Accounts" -Color Green
            Write-Host ""
        } else {
            Write-ColorOutput "  [+] No Group Managed Service Accounts found" -Color Green
        }
        
        return @{
            gMSAs = $gMSAs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing gMSA: $_" -Color Red
        return $null
    }
}

function Get-DCSyncRightsAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DCSYNC RIGHTS AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Checking for accounts with DCSync rights via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=domainDNS)"
        
        $DomainObject = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("nTSecurityDescriptor", "distinguishedName") -DC $DC -Cred $Cred
        
        if ($DomainObject) {
            Write-ColorOutput "  [*] DCSync rights analysis requires security descriptor parsing" -Color Yellow
            Write-ColorOutput "  [*] Domain Admins and Enterprise Admins have DCSync rights by default" -Color Gray
            
            $Findings += @{
                Title = "DCSync Rights Analysis"
                Severity = "INFO"
                Description = "Manual review required: Check domain root ACL for DS-Replication-Get-Changes rights"
                Details = "Use ACL traversal analysis above or BloodHound for detailed ACL analysis"
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing DCSync rights: $_" -Color Red
        return $null
    }
}

function Get-ExchangeServerAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "EXCHANGE SERVER DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting Exchange servers via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(servicePrincipalName=*exchange*)"
        
        $ExchangeServers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "name", "dNSHostName", "servicePrincipalName") -DC $DC -Cred $Cred
        
        if ($ExchangeServers) {
            Write-ColorOutput "  [+] Found $($ExchangeServers.Count) Exchange servers" -Color Green
            Write-Host ""
        } else {
            Write-ColorOutput "  [+] No Exchange servers detected" -Color Green
        }
        
        return @{
            ExchangeServers = $ExchangeServers
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting Exchange servers: $_" -Color Red
        return $null
    }
}

function Get-OutdatedOSAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "OUTDATED OPERATING SYSTEM DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting outdated operating systems via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=computer)"
        
        $Properties = @("distinguishedName", "name", "operatingSystem", "operatingSystemVersion")
        $Computers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        $OutdatedOS = @()
        $OutdatedVersions = @("Windows Server 2008", "Windows Server 2008 R2", "Windows Server 2012", "Windows 7", "Windows 8", "Windows 8.1")
        
        foreach ($Computer in $Computers) {
            if ($Computer.operatingSystem) {
                foreach ($Outdated in $OutdatedVersions) {
                    if ($Computer.operatingSystem -like "*$Outdated*") {
                        $OutdatedOS += $Computer
                        break
                    }
                }
            }
        }
        
        if ($OutdatedOS.Count -gt 0) {
            $Findings += @{
                Title = "Outdated Operating Systems Detected"
                Severity = "HIGH"
                Description = "$($OutdatedOS.Count) computers are running outdated/unsupported operating systems"
                Details = ($OutdatedOS | Select-Object -First 20 | ForEach-Object { "$($_.name): $($_.operatingSystem)" })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            OutdatedOS = $OutdatedOS
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting outdated OS: $_" -Color Red
        return $null
    }
}

function Get-AzureADConnectAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "AZURE AD CONNECT DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting Azure AD Connect accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $AzureADConnectUsers = @()
        
        $Patterns = @("*MSOL_*", "*AzureAD*", "*AAD_*", "*Sync_*")
        foreach ($Pattern in $Patterns) {
            $Filter = "(sAMAccountName=$Pattern)"
            $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "sAMAccountName", "memberOf", "userAccountControl") -DC $DC -Cred $Cred
            if ($Users) {
                $AzureADConnectUsers += $Users
            }
        }
        
        if ($AzureADConnectUsers.Count -gt 0) {
            Write-ColorOutput "  [+] Found $($AzureADConnectUsers.Count) potential Azure AD Connect accounts" -Color Green
            Write-Host ""
            
            foreach ($User in $AzureADConnectUsers) {
                if ($User.memberOf) {
                    $MemberOf = if ($User.memberOf -is [array]) { $User.memberOf } else { @($User.memberOf) }
                    foreach ($GroupDN in $MemberOf) {
                        if ($GroupDN -like "*Domain Admins*" -or $GroupDN -like "*Enterprise Admins*") {
                            $Findings += @{
                                Title = "Azure AD Connect Account in Admin Group"
                                Severity = "CRITICAL"
                                Description = "Azure AD Connect account $($User.sAMAccountName) is in admin group"
                                Details = "Azure AD Connect accounts should not be in admin groups"
                            }
                            break
                        }
                    }
                }
            }
        } else {
            Write-ColorOutput "  [+] No Azure AD Connect accounts detected" -Color Green
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            AzureADConnectUsers = $AzureADConnectUsers
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting Azure AD Connect: $_" -Color Red
        return $null
    }
}

function Write-SummaryReport {
    param($AllFindings)
    
    Write-Host ""
    Write-Host "    ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "    ║                    SECURITY AUDIT SUMMARY                         ║" -ForegroundColor Magenta
    Write-Host "    ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    $CriticalCount = ($AllFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $HighCount = ($AllFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $MediumCount = ($AllFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $LowCount = ($AllFindings | Where-Object { $_.Severity -eq "LOW" }).Count
    $InfoCount = ($AllFindings | Where-Object { $_.Severity -eq "INFO" }).Count
    
    Write-Host "    ┌───────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "    │ Findings by Severity:                                              │" -ForegroundColor DarkGray
    Write-Host "    ├───────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    
    Write-Host "    │ " -NoNewline -ForegroundColor DarkGray
    Write-Host "CRITICAL: " -NoNewline -ForegroundColor Red
    Write-Host ("{0,5}" -f $CriticalCount) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    if ($CriticalCount -gt 0) {
        Write-Host "⚠️  IMMEDIATE ACTION REQUIRED" -ForegroundColor Red
    } else {
        Write-Host "✓" -ForegroundColor Green
    }
    
    Write-Host "    │ " -NoNewline -ForegroundColor DarkGray
    Write-Host "HIGH:     " -NoNewline -ForegroundColor Magenta
    Write-Host ("{0,5}" -f $HighCount) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    if ($HighCount -gt 0) {
        Write-Host "⚠️  HIGH PRIORITY" -ForegroundColor Magenta
    } else {
        Write-Host "✓" -ForegroundColor Green
    }
    
    Write-Host "    │ " -NoNewline -ForegroundColor DarkGray
    Write-Host "MEDIUM:   " -NoNewline -ForegroundColor Yellow
    Write-Host ("{0,5}" -f $MediumCount) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    if ($MediumCount -gt 0) {
        Write-Host "⚠️  REVIEW RECOMMENDED" -ForegroundColor Yellow
    } else {
        Write-Host "✓" -ForegroundColor Green
    }
    
    Write-Host "    │ " -NoNewline -ForegroundColor DarkGray
    Write-Host "LOW:      " -NoNewline -ForegroundColor Gray
    Write-Host ("{0,5}" -f $LowCount) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    Write-Host "✓" -ForegroundColor Green
    
    Write-Host "    │ " -NoNewline -ForegroundColor DarkGray
    Write-Host "INFO:     " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,5}" -f $InfoCount) -NoNewline -ForegroundColor White
    Write-Host " " -NoNewline
    Write-Host "✓" -ForegroundColor Green
    
    Write-Host "    └───────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    
    $TotalFindings = $AllFindings.Count
    Write-Host "    " -NoNewline
    Write-Host "Total Findings: " -NoNewline -ForegroundColor Cyan
    Write-Host "$TotalFindings" -ForegroundColor White
    Write-Host ""
    
    if ($CriticalCount -gt 0 -or $HighCount -gt 0) {
        Write-Host "    " -NoNewline
        Write-Host "⚠️  " -NoNewline -ForegroundColor Red
        Write-Host "CRITICAL and HIGH severity findings require immediate attention!" -ForegroundColor Red
        Write-Host ""
    }
}

#endregion

#region Advanced Security Audit Features

function Get-SYSVOLGPOScriptAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SYSVOL / GPO SCRIPT AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing SYSVOL and GPO scripts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=groupPolicyContainer)"
        
        $GPOs = Invoke-LDAPQuery -SearchBase "CN=Policies,CN=System,$DomainDN" -LDAPFilter $Filter -Properties @("distinguishedName", "name", "gPCFileSysPath", "nTSecurityDescriptor") -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [*] Found $($GPOs.Count) GPOs" -Color Green
        Write-ColorOutput "  [*] Note: Full script analysis requires SYSVOL file system access" -Color Yellow
        Write-ColorOutput "  [*] Checking GPO ACLs for script-related misconfigurations..." -Color Cyan
        Write-Host ""
        
        # Check GPO ACLs for dangerous permissions
        $DangerousGPOACLs = @()
        foreach ($GPO in $GPOs) {
            if ($GPO.nTSecurityDescriptor) {
                try {
                    $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $SDObj.SetSecurityDescriptorBinaryForm($GPO.nTSecurityDescriptor)
                    $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    $ACLEntries = Parse-SDDL -SDDL $SDDL
                    
                    foreach ($ACE in $ACLEntries) {
                        if ($ACE.Type -eq "A" -and ($ACE.Rights -eq "WD" -or $ACE.Rights -eq "WO" -or $ACE.Rights -eq "GA")) {
                            $DangerousGPOACLs += @{
                                GPO = $GPO.name
                                Right = $ACE.Rights
                                Subject = $ACE.Subject
                            }
                        }
                    }
                } catch { }
            }
        }
        
        if ($DangerousGPOACLs.Count -gt 0) {
            $Findings += @{
                Title = "GPOs with Dangerous ACLs (WriteDACL/WriteOwner/GenericAll)"
                Severity = "CRITICAL"
                Description = "$($DangerousGPOACLs.Count) GPOs have dangerous ACLs allowing modification"
                Details = ($DangerousGPOACLs | Select-Object -First 20 | ForEach-Object { "$($_.GPO): $($_.Right)" })
            }
        }
        
        $Findings += @{
            Title = "SYSVOL Script Audit"
            Severity = "INFO"
            Description = "Full script analysis requires SYSVOL file system access"
            Details = "Use tools like Get-GPPPassword, manually check SYSVOL shares, or use file system enumeration tools"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            GPOs = $GPOs
            DangerousACLs = $DangerousGPOACLs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing SYSVOL/GPO scripts: $_" -Color Red
        return $null
    }
}

function Get-GPODelegationAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "GPO DELEGATION & SECURITY FILTERING MISCONFIGURATIONS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing GPO delegation and security filtering via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=groupPolicyContainer)"
        
        $GPOs = Invoke-LDAPQuery -SearchBase "CN=Policies,CN=System,$DomainDN" -LDAPFilter $Filter -Properties @("distinguishedName", "name", "nTSecurityDescriptor", "gPCFileSysPath") -DC $DC -Cred $Cred
        
        $NonDefaultACLs = @()
        $WriteDACLGPOs = @()
        $WriteOwnerGPOs = @()
        
        foreach ($GPO in $GPOs) {
            if ($GPO.nTSecurityDescriptor) {
                try {
                    $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $SDObj.SetSecurityDescriptorBinaryForm($GPO.nTSecurityDescriptor)
                    $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    $ACLEntries = Parse-SDDL -SDDL $SDDL
                    
                    foreach ($ACE in $ACLEntries) {
                        if ($ACE.Type -eq "A") {
                            if ($ACE.Rights -eq "WD") {
                                $WriteDACLGPOs += $GPO
                            }
                            if ($ACE.Rights -eq "WO") {
                                $WriteOwnerGPOs += $GPO
                            }
                            if ($ACE.Rights -eq "GA" -or $ACE.Rights -eq "GW") {
                                $NonDefaultACLs += $GPO
                            }
                        }
                    }
                } catch { }
            }
        }
        
        if ($WriteDACLGPOs.Count -gt 0) {
            $Findings += @{
                Title = "GPOs with WriteDACL Permissions"
                Severity = "CRITICAL"
                Description = "$($WriteDACLGPOs.Count) GPOs have WriteDACL permissions (allows ACL modification)"
                Details = ($WriteDACLGPOs | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        if ($WriteOwnerGPOs.Count -gt 0) {
            $Findings += @{
                Title = "GPOs with WriteOwner Permissions"
                Severity = "CRITICAL"
                Description = "$($WriteOwnerGPOs.Count) GPOs have WriteOwner permissions"
                Details = ($WriteOwnerGPOs | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            NonDefaultACLs = $NonDefaultACLs
            WriteDACLGPOs = $WriteDACLGPOs
            WriteOwnerGPOs = $WriteOwnerGPOs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing GPO delegation: $_" -Color Red
        return $null
    }
}

function Get-TieredAdministrationAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "TIERED ADMINISTRATION MODEL VIOLATIONS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing tiered administration model violations via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Get Tier0 groups
        $Tier0Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        $Tier0Members = @()
        
        foreach ($GroupName in $Tier0Groups) {
            $Filter = "(sAMAccountName=$GroupName)"
            $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName") -DC $DC -Cred $Cred
            if ($Group -and $Group.Count -gt 0) {
                $Members = Resolve-GroupMembership -GroupDN $Group[0].distinguishedName -DC $DC -Cred $Cred
                $Tier0Members += $Members
            }
        }
        
        # Get service accounts
        $ServiceAccountFilter = "(&(servicePrincipalName=*)(objectClass=user))"
        $ServiceAccounts = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $ServiceAccountFilter -Properties @("distinguishedName", "sAMAccountName", "memberOf") -DC $DC -Cred $Cred
        
        # Check if service accounts are in Tier0 groups
        $ServiceAccountsInTier0 = @()
        foreach ($ServiceAccount in $ServiceAccounts) {
            if ($ServiceAccount.memberOf) {
                $MemberOf = if ($ServiceAccount.memberOf -is [array]) { $ServiceAccount.memberOf } else { @($ServiceAccount.memberOf) }
                foreach ($GroupDN in $MemberOf) {
                    foreach ($Tier0Group in $Tier0Groups) {
                        if ($GroupDN -like "*$Tier0Group*") {
                            $ServiceAccountsInTier0 += $ServiceAccount
                            break
                        }
                    }
                }
            }
        }
        
        if ($ServiceAccountsInTier0.Count -gt 0) {
            $Findings += @{
                Title = "Service Accounts in Tier0 Groups"
                Severity = "CRITICAL"
                Description = "$($ServiceAccountsInTier0.Count) service accounts are members of Tier0 groups"
                Details = ($ServiceAccountsInTier0 | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        Write-ColorOutput "  [*] Note: Tier0 login detection requires event log analysis" -Color Yellow
        Write-ColorOutput "  [*] Note: Credential caching detection requires registry/event log analysis" -Color Yellow
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Tier0Members = $Tier0Members
            ServiceAccountsInTier0 = $ServiceAccountsInTier0
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing tiered administration: $_" -Color Red
        return $null
    }
}

function Get-LDAPHardeningAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "LDAP SIGNING / CHANNEL BINDING / NTLM HARDENING AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing LDAP/NTLM hardening via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=domainDNS)"
        
        $Properties = @("distinguishedName", "dSHeuristics", "msDS-Other-Settings")
        $DomainInfo = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        Write-ColorOutput "  [*] LDAP signing and channel binding settings require registry/domain policy analysis" -Color Yellow
        Write-ColorOutput "  [*] Check domain controllers for:" -Color Cyan
        Write-ColorOutput "      - LDAP signing requirement" -Color Gray
        Write-ColorOutput "      - LDAP channel binding requirement" -Color Gray
        Write-ColorOutput "      - NTLM authentication restrictions" -Color Gray
        Write-ColorOutput "      - SMB signing requirements" -Color Gray
        Write-Host ""
        
        # Check for NTLM-related settings
        if ($DomainInfo -and $DomainInfo[0].dSHeuristics) {
            $DSHeuristics = $DomainInfo[0].dSHeuristics
            Write-ColorOutput "  [*] DS Heuristics: $DSHeuristics" -Color Gray
        }
        
        $Findings += @{
            Title = "LDAP/NTLM Hardening Analysis"
            Severity = "INFO"
            Description = "LDAP signing, channel binding, and NTLM hardening require registry/domain policy analysis"
            Details = "Check domain controllers registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            DomainInfo = $DomainInfo
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing LDAP hardening: $_" -Color Red
        return $null
    }
}

function Get-KerberosHardeningAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "KERBEROS HARDENING AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Kerberos hardening via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Check krbtgt account
        $Filter = "(sAMAccountName=krbtgt)"
        $krbtgt = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "pwdLastSet", "userAccountControl") -DC $DC -Cred $Cred
        
        if ($krbtgt -and $krbtgt.Count -gt 0) {
            if ($krbtgt[0].pwdLastSet) {
                try {
                    $PwdLastSet = [DateTime]::FromFileTime([int64]$krbtgt[0].pwdLastSet)
                    $DaysSince = (New-TimeSpan -Start $PwdLastSet -End (Get-Date)).Days
                    
                    if ($DaysSince -gt 365) {
                        $Findings += @{
                            Title = "krbtgt Password Not Rotated (>365 days)"
                            Severity = "CRITICAL"
                            Description = "krbtgt account password has not been changed in $DaysSince days (recommended: rotate every 180 days)"
                            Details = "Last changed: $PwdLastSet"
                        }
                    } elseif ($DaysSince -gt 180) {
                        $Findings += @{
                            Title = "krbtgt Password Not Rotated (>180 days)"
                            Severity = "HIGH"
                            Description = "krbtgt account password has not been changed in $DaysSince days (recommended: rotate every 180 days)"
                            Details = "Last changed: $PwdLastSet"
                        }
                    }
                } catch { }
            }
        }
        
        # Check for accounts using RC4 (requires additional analysis)
        Write-ColorOutput "  [*] RC4-HMAC detection requires Kerberos ticket analysis" -Color Yellow
        Write-ColorOutput "  [*] Check for accounts with 'Do not require Kerberos pre-authentication' (already detected above)" -Color Gray
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            krbtgt = $krbtgt
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing Kerberos hardening: $_" -Color Red
        return $null
    }
}

function Get-SMBShareAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SMB / CIFS SHARE ENUMERATION & MISCONFIG REVIEW"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing SMB shares..." -Color Cyan
        
        Write-ColorOutput "  [*] SMB share enumeration requires network access or WMI queries" -Color Yellow
        Write-ColorOutput "  [*] Use tools like Get-SMBShare, net view, or WMI queries" -Color Yellow
        Write-ColorOutput "  [*] Check for:" -Color Cyan
        Write-ColorOutput "      - Shares with Everyone/Users WRITE access" -Color Gray
        Write-ColorOutput "      - Sensitive shares exposed" -Color Gray
        Write-ColorOutput "      - Administrative shares accessible from non-Tier0" -Color Gray
        Write-ColorOutput "      - Misconfigured NETLOGON/SYSVOL permissions" -Color Gray
        Write-Host ""
        
        $Findings += @{
            Title = "SMB Share Audit"
            Severity = "INFO"
            Description = "SMB share enumeration requires network access or WMI queries"
            Details = "Use Get-SMBShare, net view, or WMI Win32_Share queries on domain controllers and file servers"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing SMB shares: $_" -Color Red
        return $null
    }
}

function Get-gMSAPasswordRetrievalAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "gMSA PASSWORD RETRIEVAL AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing gMSA password retrieval permissions via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectCategory=msDS-GroupManagedServiceAccount)"
        
        $Properties = @("distinguishedName", "name", "msDS-GroupMSAMembership", "msDS-ManagedPasswordId", "nTSecurityDescriptor")
        $gMSAs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($gMSAs) {
            Write-ColorOutput "  [+] Found $($gMSAs.Count) gMSAs" -Color Green
            Write-Host ""
            
            foreach ($gMSA in $gMSAs) {
                if ($gMSA.nTSecurityDescriptor) {
                    try {
                        $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $SDObj.SetSecurityDescriptorBinaryForm($gMSA.nTSecurityDescriptor)
                        $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                        $ACLEntries = Parse-SDDL -SDDL $SDDL
                        
                        # Check for ReadProperty on msDS-ManagedPassword
                        foreach ($ACE in $ACLEntries) {
                            if ($ACE.Type -eq "A" -and ($ACE.Rights -eq "RP" -or $ACE.Rights -eq "GA" -or $ACE.Rights -eq "GW")) {
                                $SubjectSID = $ACE.Subject
                                $SubjectName = Resolve-SIDToName -SID $SubjectSID -DC $DC -Cred $Cred
                                
                                if ($SubjectName -is [hashtable]) {
                                    $SubjectName = $SubjectName.sAMAccountName
                                }
                                
                                $Findings += @{
                                    Title = "gMSA Password Retrieval Permission"
                                    Severity = "HIGH"
                                    Description = "Account/Group '$SubjectName' can retrieve password for gMSA '$($gMSA.name)'"
                                    Details = "gMSA: $($gMSA.name), Subject: $SubjectName, Right: $($ACE.Rights)"
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            gMSAs = $gMSAs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing gMSA password retrieval: $_" -Color Red
        return $null
    }
}

function Get-DCSyncShadowPermissionsAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DCSYNC SHADOW PERMISSIONS AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing DCSync shadow permissions via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Check domain root
        $Filter = "(objectClass=domainDNS)"
        $DomainObject = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("nTSecurityDescriptor", "distinguishedName") -DC $DC -Cred $Cred
        
        if ($DomainObject -and $DomainObject[0].nTSecurityDescriptor) {
            try {
                $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $SDObj.SetSecurityDescriptorBinaryForm($DomainObject[0].nTSecurityDescriptor)
                $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                $ACLEntries = Parse-SDDL -SDDL $SDDL
                
                foreach ($ACE in $ACLEntries) {
                    if ($ACE.Type -eq "A" -and ($ACE.Rights -eq "DC" -or $ACE.Rights -eq "CA")) {
                        $SubjectSID = $ACE.Subject
                        $SubjectName = Resolve-SIDToName -SID $SubjectSID -DC $DC -Cred $Cred
                        
                        if ($SubjectName -is [hashtable]) {
                            $SubjectName = $SubjectName.sAMAccountName
                        }
                        
                        # Check if it's a group - if so, find all members
                        $SubjectFilter = "(objectSid=$SubjectSID)"
                        $SubjectObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $SubjectFilter -Properties @("objectClass", "sAMAccountName") -DC $DC -Cred $Cred
                        
                        if ($SubjectObj -and $SubjectObj[0].objectClass -contains "group") {
                            $GroupMembers = Resolve-GroupMembership -GroupDN $SubjectObj[0].distinguishedName -DC $DC -Cred $Cred
                            
                            foreach ($MemberDN in $GroupMembers) {
                                $MemberFilter = "(distinguishedName=$($MemberDN -replace '\(', '\28' -replace '\)', '\29'))"
                                $MemberObj = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $MemberFilter -Properties @("objectClass", "sAMAccountName") -DC $DC -Cred $Cred
                                
                                if ($MemberObj -and $MemberObj[0].objectClass -contains "user") {
                                    $Findings += @{
                                        Title = "DCSync via Nested Group Membership"
                                        Severity = "CRITICAL"
                                        Description = "User '$($MemberObj[0].sAMAccountName)' has DCSync rights via group '$SubjectName'"
                                        Details = "Path: $($MemberObj[0].sAMAccountName) -> Member of -> $SubjectName -> has DCSync on Domain Root"
                                    }
                                }
                            }
                        } else {
                            $Findings += @{
                                Title = "DCSync Rights on Domain Root"
                                Severity = "CRITICAL"
                                Description = "Account/Group '$SubjectName' has DCSync rights on domain root"
                                Details = "Right: $($ACE.Rights), Subject: $SubjectName"
                            }
                        }
                    }
                }
            } catch { }
        }
        
        # Check OUs for DCSync rights
        $OUFilter = "(objectClass=organizationalUnit)"
        $OUs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $OUFilter -Properties @("distinguishedName", "name", "nTSecurityDescriptor") -DC $DC -Cred $Cred
        
        foreach ($OU in $OUs) {
            if ($OU.nTSecurityDescriptor) {
                try {
                    $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $SDObj.SetSecurityDescriptorBinaryForm($OU.nTSecurityDescriptor)
                    $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    $ACLEntries = Parse-SDDL -SDDL $SDDL
                    
                    foreach ($ACE in $ACLEntries) {
                        if ($ACE.Type -eq "A" -and ($ACE.Rights -eq "DC" -or $ACE.Rights -eq "CA")) {
                            $SubjectSID = $ACE.Subject
                            $SubjectName = Resolve-SIDToName -SID $SubjectSID -DC $DC -Cred $Cred
                            
                            if ($SubjectName -is [hashtable]) {
                                $SubjectName = $SubjectName.sAMAccountName
                            }
                            
                            $Findings += @{
                                Title = "DCSync Rights on OU"
                                Severity = "CRITICAL"
                                Description = "Account/Group '$SubjectName' has DCSync rights on OU '$($OU.name)'"
                                Details = "OU: $($OU.name), Right: $($ACE.Rights), Subject: $SubjectName"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing DCSync shadow permissions: $_" -Color Red
        return $null
    }
}

function Get-ExchangeHybridAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "EXCHANGE / EWS / HYBRID IDENTITY ATTACK SURFACE"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Exchange and hybrid identity attack surface via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Exchange Trusted Subsystem group
        $Filter = "(sAMAccountName=Exchange Trusted Subsystem)"
        $ExchangeTrustedSubsystem = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "member") -DC $DC -Cred $Cred
        
        if ($ExchangeTrustedSubsystem -and $ExchangeTrustedSubsystem.Count -gt 0) {
            $Members = Resolve-GroupMembership -GroupDN $ExchangeTrustedSubsystem[0].distinguishedName -DC $DC -Cred $Cred
            Write-ColorOutput "  [+] Exchange Trusted Subsystem group has $($Members.Count) members" -Color Yellow
            Write-Host ""
            
            $Findings += @{
                Title = "Exchange Trusted Subsystem Group Members"
                Severity = "HIGH"
                Description = "Exchange Trusted Subsystem group has $($Members.Count) members (high privilege group)"
                Details = "This group has extensive permissions in Exchange environments"
            }
        }
        
        # Exchange-related groups
        $ExchangeGroups = @("Organization Management", "Exchange Servers", "Exchange Trusted Subsystem", "Exchange Windows Permissions")
        foreach ($GroupName in $ExchangeGroups) {
            $GroupFilter = "(sAMAccountName=$GroupName)"
            $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $GroupFilter -Properties @("distinguishedName", "member") -DC $DC -Cred $Cred
            
            if ($Group -and $Group.Count -gt 0) {
                $Members = Resolve-GroupMembership -GroupDN $Group[0].distinguishedName -DC $DC -Cred $Cred
                if ($Members.Count -gt 0) {
                    Write-ColorOutput "  [*] $GroupName : $($Members.Count) members" -Color Yellow
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            ExchangeGroups = $ExchangeGroups
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing Exchange hybrid: $_" -Color Red
        return $null
    }
}

function Get-FSMORolesAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "FSMO ROLES & DOMAIN CONTROLLER HEALTH AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing FSMO roles and DC health via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # Get domain controllers
        $Filter = "(primaryGroupID=516)"
        $DCs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "userAccountControl") -DC $DC -Cred $Cred
        
        if ($DCs) {
            Write-ColorOutput "  [+] Found $($DCs.Count) domain controllers" -Color Green
            Write-Host ""
            
            # Check for unconstrained delegation on DCs
            $DCsWithUnconstrainedDelegation = @()
            foreach ($DC in $DCs) {
                $UAC = if ($DC.userAccountControl) { [int]$DC.userAccountControl } else { 0 }
                if (($UAC -band 0x80000) -ne 0) {
                    $DCsWithUnconstrainedDelegation += $DC
                }
            }
            
            if ($DCsWithUnconstrainedDelegation.Count -gt 0) {
                $Findings += @{
                    Title = "Domain Controllers with Unconstrained Delegation"
                    Severity = "CRITICAL"
                    Description = "$($DCsWithUnconstrainedDelegation.Count) domain controllers have unconstrained delegation enabled"
                    Details = ($DCsWithUnconstrainedDelegation | Select-Object -First 20 | ForEach-Object { $_.name })
                }
            }
            
            # Check for outdated OS on DCs
            $OutdatedDCs = @()
            $OutdatedVersions = @("Windows Server 2008", "Windows Server 2008 R2", "Windows Server 2012")
            foreach ($DC in $DCs) {
                if ($DC.operatingSystem) {
                    foreach ($Outdated in $OutdatedVersions) {
                        if ($DC.operatingSystem -like "*$Outdated*") {
                            $OutdatedDCs += $DC
                            break
                        }
                    }
                }
            }
            
            if ($OutdatedDCs.Count -gt 0) {
                $Findings += @{
                    Title = "Outdated Domain Controllers"
                    Severity = "CRITICAL"
                    Description = "$($OutdatedDCs.Count) domain controllers are running outdated/unsupported OS"
                    Details = ($OutdatedDCs | Select-Object -First 20 | ForEach-Object { "$($_.name): $($_.operatingSystem)" })
                }
            }
        }
        
        Write-ColorOutput "  [*] FSMO role enumeration requires specific LDAP queries or Get-ADDomain cmdlet" -Color Yellow
        Write-ColorOutput "  [*] Roles: PDC Emulator, RID Master, Infrastructure Master, Schema Master, Domain Naming Master" -Color Gray
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            DCs = $DCs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing FSMO roles: $_" -Color Red
        return $null
    }
}

function Get-DNSMisconfigurationAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DNS MISCONFIGURATION AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing DNS misconfigurations via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # DNSAdmins group
        $Filter = "(sAMAccountName=DNSAdmins)"
        $DNSAdmins = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "member") -DC $DC -Cred $Cred
        
        if ($DNSAdmins -and $DNSAdmins.Count -gt 0) {
            $Members = Resolve-GroupMembership -GroupDN $DNSAdmins[0].distinguishedName -DC $DC -Cred $Cred
            Write-ColorOutput "  [+] DNSAdmins group has $($Members.Count) members" -Color Yellow
            Write-Host ""
            
            if ($Members.Count -gt 0) {
                $Findings += @{
                    Title = "DNSAdmins Group Members"
                    Severity = "HIGH"
                    Description = "DNSAdmins group has $($Members.Count) members (can load DLLs on DNS servers)"
                    Details = "DNSAdmins can load arbitrary DLLs on DNS servers, leading to domain compromise"
                }
            }
        }
        
        Write-ColorOutput "  [*] DNS zone configuration requires DNS server access or WMI queries" -Color Yellow
        Write-ColorOutput "  [*] Check for:" -Color Cyan
        Write-ColorOutput "      - Insecure dynamic updates" -Color Gray
        Write-ColorOutput "      - Zone transfers allowed" -Color Gray
        Write-ColorOutput "      - Insecure conditional forwarders" -Color Gray
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            DNSAdmins = $DNSAdmins
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing DNS misconfigurations: $_" -Color Red
        return $null
    }
}

function Get-SitesSubnetsDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "AD SITE & SUBNET ENUMERATION (DETAILED)"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Enumerating AD sites and subnets via LDAP..." -Color Cyan
        
        $ConfigDN = "CN=Configuration,$((Get-DomainDN -Domain $Domain).Replace('DC=', 'DC='))"
        $ConfigDN = $ConfigDN -replace 'DC=([^,]+),DC=', 'CN=Configuration,DC=$1,DC='
        
        # Try to get sites
        $SiteFilter = "(objectClass=site)"
        $Sites = Invoke-LDAPQuery -SearchBase "CN=Sites,$ConfigDN" -LDAPFilter $SiteFilter -Properties @("distinguishedName", "name", "description") -DC $DC -Cred $Cred -ErrorAction SilentlyContinue
        
        if (-not $Sites) {
            # Try alternative path
            $ConfigBase = "CN=Configuration," + (Get-DomainDN -Domain $Domain)
            $Sites = Invoke-LDAPQuery -SearchBase "CN=Sites,$ConfigBase" -LDAPFilter $SiteFilter -Properties @("distinguishedName", "name") -DC $DC -Cred $Cred -ErrorAction SilentlyContinue
        }
        
        if ($Sites) {
            Write-ColorOutput "  [+] Found $($Sites.Count) AD sites" -Color Green
            Write-Host ""
        } else {
            Write-ColorOutput "  [!] Could not enumerate sites (may require Configuration partition access)" -Color Yellow
        }
        
        # Subnet enumeration
        $SubnetFilter = "(objectClass=subnet)"
        $Subnets = Invoke-LDAPQuery -SearchBase "CN=Subnets,CN=Sites,$ConfigDN" -LDAPFilter $SubnetFilter -Properties @("distinguishedName", "name", "siteObject") -DC $DC -Cred $Cred -ErrorAction SilentlyContinue
        
        if ($Subnets) {
            Write-ColorOutput "  [+] Found $($Subnets.Count) subnets" -Color Green
            Write-Host ""
        }
        
        return @{
            Sites = $Sites
            Subnets = $Subnets
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error enumerating sites and subnets: $_" -Color Red
        return $null
    }
}

function Get-FGPPDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "FINE-GRAINED PASSWORD POLICY (FGPP) DETAILED AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Fine-Grained Password Policies via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=msDS-PasswordSettings)"
        
        $Properties = @("distinguishedName", "name", "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo", "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled")
        $FGPPs = Invoke-LDAPQuery -SearchBase "CN=Password Settings Container,CN=System,$DomainDN" -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($FGPPs) {
            Write-ColorOutput "  [+] Found $($FGPPs.Count) Fine-Grained Password Policies" -Color Green
            Write-Host ""
            
            foreach ($FGPP in $FGPPs) {
                Write-ColorOutput "  [*] Policy: $($FGPP.name)" -Color Cyan
                if ($FGPP.'msDS-PasswordSettingsPrecedence') {
                    Write-ColorOutput "      Precedence: $($FGPP.'msDS-PasswordSettingsPrecedence')" -Color Gray
                }
                if ($FGPP.'msDS-PSOAppliesTo') {
                    Write-ColorOutput "      Applies To: $($FGPP.'msDS-PSOAppliesTo')" -Color Gray
                }
                
                if ($FGPP.'msDS-PasswordReversibleEncryptionEnabled' -eq $true) {
                    $Findings += @{
                        Title = "FGPP with Reversible Encryption Enabled"
                        Severity = "CRITICAL"
                        Description = "Fine-Grained Password Policy '$($FGPP.name)' has reversible encryption enabled"
                        Details = "Policy: $($FGPP.name)"
                    }
                }
                Write-Host ""
            }
        } else {
            Write-ColorOutput "  [+] No Fine-Grained Password Policies found" -Color Green
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            FGPPs = $FGPPs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing FGPP: $_" -Color Red
        return $null
    }
}

function Get-RODCDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "RODC MISCONFIGURATION AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Read-Only Domain Controllers via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(primaryGroupID=521)"
        
        $RODCs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "name", "dNSHostName", "userAccountControl") -DC $DC -Cred $Cred
        
        if ($RODCs) {
            Write-ColorOutput "  [+] Found $($RODCs.Count) Read-Only Domain Controllers" -Color Green
            Write-Host ""
            
            foreach ($RODC in $RODCs) {
                Write-ColorOutput "  [*] RODC: $($RODC.name)" -Color Cyan
                if ($RODC.dNSHostName) {
                    Write-ColorOutput "      DNS: $($RODC.dNSHostName)" -Color Gray
                }
                Write-Host ""
            }
            
            Write-ColorOutput "  [*] Check RODC password replication groups for security" -Color Yellow
            Write-ColorOutput "  [*] Review msDS-RevealedUsers and msDS-RevealedList attributes" -Color Yellow
        } else {
            Write-ColorOutput "  [+] No RODCs detected" -Color Green
        }
        
        return @{
            RODCs = $RODCs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing RODCs: $_" -Color Red
        return $null
    }
}

function Get-SPNHygieneAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SPN HYGIENE AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing SPN hygiene via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(servicePrincipalName=*)(objectClass=user))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "servicePrincipalName", "userAccountControl")
        $SPNAccounts = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($SPNAccounts) {
            Write-ColorOutput "  [+] Found $($SPNAccounts.Count) accounts with SPNs" -Color Green
            Write-Host ""
            
            # Check for duplicate SPNs
            $AllSPNs = @()
            foreach ($Account in $SPNAccounts) {
                if ($Account.servicePrincipalName) {
                    $SPNs = if ($Account.servicePrincipalName -is [array]) { $Account.servicePrincipalName } else { @($Account.servicePrincipalName) }
                    foreach ($SPN in $SPNs) {
                        $AllSPNs += @{
                            SPN = $SPN
                            User = $Account.sAMAccountName
                        }
                    }
                }
            }
            
            $SPNGroups = $AllSPNs | Group-Object -Property SPN
            $DuplicateSPNs = $SPNGroups | Where-Object { $_.Count -gt 1 }
            
            if ($DuplicateSPNs.Count -gt 0) {
                $Findings += @{
                    Title = "Duplicate Service Principal Names (SPNs)"
                    Severity = "HIGH"
                    Description = "$($DuplicateSPNs.Count) SPNs are assigned to multiple accounts"
                    Details = ($DuplicateSPNs | Select-Object -First 20 | ForEach-Object { "$($_.Name): $($_.Count) accounts" })
                }
            }
            
            # Check for SPNs on normal users (not service accounts)
            $NormalUsersWithSPNs = @()
            foreach ($Account in $SPNAccounts) {
                $UAC = if ($Account.userAccountControl) { [int]$Account.userAccountControl } else { 0 }
                $IsServiceAccount = ($UAC -band 0x1000) -ne 0  # TRUSTED_TO_AUTH_FOR_DELEGATION
                
                if (-not $IsServiceAccount) {
                    $NormalUsersWithSPNs += $Account
                }
            }
            
            if ($NormalUsersWithSPNs.Count -gt 0) {
                $Findings += @{
                    Title = "Normal Users with SPNs"
                    Severity = "MEDIUM"
                    Description = "$($NormalUsersWithSPNs.Count) normal user accounts have SPNs assigned"
                    Details = ($NormalUsersWithSPNs | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            SPNAccounts = $SPNAccounts
            DuplicateSPNs = $DuplicateSPNs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing SPN hygiene: $_" -Color Red
        return $null
    }
}

function Get-AccountLockoutPolicyDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "ACCOUNT LOCKOUT & AUDIT POLICY ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing account lockout and audit policies via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=domainDNS)"
        
        $Properties = @("lockoutThreshold", "lockoutDuration", "lockOutObservationWindow")
        $DomainInfo = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        if ($DomainInfo -and $DomainInfo[0].lockoutThreshold) {
            $Threshold = [int]$DomainInfo[0].lockoutThreshold
            Write-ColorOutput "  [+] Lockout Threshold: $Threshold" -Color Green
            
            if ($Threshold -eq 0) {
                $Findings += @{
                    Title = "Account Lockout Disabled"
                    Severity = "HIGH"
                    Description = "Account lockout is disabled (no brute force protection)"
                    Details = "LockoutThreshold is 0"
                }
            } elseif ($Threshold -gt 10) {
                $Findings += @{
                    Title = "Weak Account Lockout Threshold"
                    Severity = "MEDIUM"
                    Description = "Account lockout threshold is $Threshold (recommended: 5-10)"
                    Details = "High threshold allows more brute force attempts"
                }
            }
        }
        
        Write-ColorOutput "  [*] Audit policy analysis requires local security policy or GPO analysis" -Color Yellow
        Write-ColorOutput "  [*] Check for:" -Color Cyan
        Write-ColorOutput "      - Failure auditing state" -Color Gray
        Write-ColorOutput "      - Success auditing state" -Color Gray
        Write-ColorOutput "      - Logon auditing settings" -Color Gray
        Write-ColorOutput "      - Privilege Use auditing" -Color Gray
        Write-ColorOutput "      - DS Access auditing" -Color Gray
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            DomainInfo = $DomainInfo
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing account lockout policy: $_" -Color Red
        return $null
    }
}

function Get-NetlogonCryptoAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "NETLOGON / CRYPTO POLICIES AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing Netlogon and crypto policies..." -Color Cyan
        
        Write-ColorOutput "  [*] Netlogon secure channel enforcement requires registry analysis" -Color Yellow
        Write-ColorOutput "  [*] Check domain controllers for:" -Color Cyan
        Write-ColorOutput "      - RequireStrongKey (ZeroLogon protection)" -Color Gray
        Write-ColorOutput "      - RequireSignOrSeal" -Color Gray
        Write-ColorOutput "      - Secure RPC settings" -Color Gray
        Write-Host ""
        
        $Findings += @{
            Title = "Netlogon/Crypto Policy Analysis"
            Severity = "INFO"
            Description = "Netlogon secure channel enforcement requires registry analysis on domain controllers"
            Details = "Check HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters for RequireStrongKey and RequireSignOrSeal"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing Netlogon policies: $_" -Color Red
        return $null
    }
}

function Get-SCCMAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "SCCM/MECM AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing SCCM/MECM configuration via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # SCCM-related accounts
        $SCCMPatterns = @("*SCCM*", "*MECM*", "*ConfigMgr*", "*SMS*")
        $SCCMAccounts = @()
        
        foreach ($Pattern in $SCCMPatterns) {
            $Filter = "(|(sAMAccountName=$Pattern)(name=$Pattern)(description=$Pattern))"
            $Accounts = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "sAMAccountName", "memberOf", "description") -DC $DC -Cred $Cred
            if ($Accounts) {
                $SCCMAccounts += $Accounts
            }
        }
        
        if ($SCCMAccounts.Count -gt 0) {
            Write-ColorOutput "  [+] Found $($SCCMAccounts.Count) potential SCCM/MECM accounts" -Color Green
            Write-Host ""
            
            # Check if SCCM accounts are in Domain Admins
            $SCCMInDomainAdmins = @()
            foreach ($Account in $SCCMAccounts) {
                if ($Account.memberOf) {
                    $MemberOf = if ($Account.memberOf -is [array]) { $Account.memberOf } else { @($Account.memberOf) }
                    foreach ($GroupDN in $MemberOf) {
                        if ($GroupDN -like "*Domain Admins*") {
                            $SCCMInDomainAdmins += $Account
                            break
                        }
                    }
                }
            }
            
            if ($SCCMInDomainAdmins.Count -gt 0) {
                $Findings += @{
                    Title = "SCCM/MECM Accounts in Domain Admins"
                    Severity = "CRITICAL"
                    Description = "$($SCCMInDomainAdmins.Count) SCCM/MECM accounts are in Domain Admins group"
                    Details = ($SCCMInDomainAdmins | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
                }
            }
        } else {
            Write-ColorOutput "  [+] No SCCM/MECM accounts detected" -Color Green
        }
        
        Write-ColorOutput "  [*] SCCM Network Access Account detection requires SCCM database access" -Color Yellow
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            SCCMAccounts = $SCCMAccounts
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing SCCM: $_" -Color Red
        return $null
    }
}

function Get-StaleObjectAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "STALE OBJECT DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting stale objects via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $DaysThreshold = 365
        
        # Stale users (no logon in X days)
        $UserFilter = "(&(objectClass=user)(objectCategory=person))"
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $UserFilter -Properties @("distinguishedName", "sAMAccountName", "lastLogonTimestamp", "whenChanged") -DC $DC -Cred $Cred
        
        $StaleUsers = @()
        foreach ($User in $Users) {
            if ($User.lastLogonTimestamp) {
                try {
                    $LastLogon = [DateTime]::FromFileTime([int64]$User.lastLogonTimestamp)
                    $DaysSince = (New-TimeSpan -Start $LastLogon -End (Get-Date)).Days
                    if ($DaysSince -gt $DaysThreshold) {
                        $StaleUsers += $User
                    }
                } catch { }
            } elseif ($User.whenChanged) {
                try {
                    $WhenChanged = [DateTime]$User.whenChanged
                    $DaysSince = (New-TimeSpan -Start $WhenChanged -End (Get-Date)).Days
                    if ($DaysSince -gt $DaysThreshold) {
                        $StaleUsers += $User
                    }
                } catch { }
            }
        }
        
        if ($StaleUsers.Count -gt 0) {
            $Findings += @{
                Title = "Stale User Accounts"
                Severity = "MEDIUM"
                Description = "$($StaleUsers.Count) user accounts appear to be stale (no activity in $DaysThreshold+ days)"
                Details = ($StaleUsers | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Stale groups (no members)
        $GroupFilter = "(objectClass=group)"
        $Groups = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $GroupFilter -Properties @("distinguishedName", "sAMAccountName", "member") -DC $DC -Cred $Cred
        
        $EmptyGroups = @()
        foreach ($Group in $Groups) {
            if (-not $Group.member -or ($Group.member -is [array] -and $Group.member.Count -eq 0)) {
                $EmptyGroups += $Group
            }
        }
        
        if ($EmptyGroups.Count -gt 0) {
            $Findings += @{
                Title = "Empty Groups (Potential Stale)"
                Severity = "LOW"
                Description = "$($EmptyGroups.Count) groups have no members"
                Details = ($EmptyGroups | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            StaleUsers = $StaleUsers
            EmptyGroups = $EmptyGroups
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting stale objects: $_" -Color Red
        return $null
    }
}

function Get-ADCSVulnerabilityAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "ADCS VULNERABILITY AUDIT (ESC8/ESC9/ESC10)"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing ADCS for known vulnerabilities via LDAP..." -Color Cyan
        
        $ConfigDN = "CN=Configuration," + (Get-DomainDN -Domain $Domain)
        $TemplateFilter = "(objectCategory=pKICertificateTemplate)"
        
        $Templates = Invoke-LDAPQuery -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigDN" -LDAPFilter $TemplateFilter -Properties @("distinguishedName", "name", "pKIEnrollmentFlag", "pKIExtendedKeyUsage", "pKIKeyUsage", "nTSecurityDescriptor") -DC $DC -Cred $Cred
        
        if ($Templates) {
            Write-ColorOutput "  [+] Found $($Templates.Count) certificate templates" -Color Green
            Write-Host ""
            
            $VulnerableTemplates = @()
            
            foreach ($Template in $Templates) {
                $IsVulnerable = $false
                $VulnReasons = @()
                
                # ESC8: Web Enrollment enabled
                if ($Template.pKIEnrollmentFlag) {
                    $EnrollmentFlag = [int]$Template.pKIEnrollmentFlag
                    # 0x00000020 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    # Check if template allows enrollment
                    if (($EnrollmentFlag -band 0x00000020) -ne 0) {
                        $IsVulnerable = $true
                        $VulnReasons += "Enrollment allowed"
                    }
                }
                
                # Check if Authenticated Users can enroll
                if ($Template.nTSecurityDescriptor) {
                    try {
                        $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $SDObj.SetSecurityDescriptorBinaryForm($Template.nTSecurityDescriptor)
                        $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                        if ($SDDL -like "*S-1-5-11*") {  # Authenticated Users SID
                            $IsVulnerable = $true
                            $VulnReasons += "Authenticated Users can enroll"
                        }
                    } catch { }
                }
                
                if ($IsVulnerable) {
                    $VulnerableTemplates += @{
                        Name = $Template.name
                        Reasons = $VulnReasons
                    }
                }
            }
            
            if ($VulnerableTemplates.Count -gt 0) {
                $Findings += @{
                    Title = "Potentially Vulnerable Certificate Templates"
                    Severity = "HIGH"
                    Description = "$($VulnerableTemplates.Count) certificate templates may be vulnerable to ESC8/ESC9/ESC10"
                    Details = ($VulnerableTemplates | ForEach-Object { "$($_.Name): $($_.Reasons -join ', ')" })
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Templates = $Templates
            VulnerableTemplates = $VulnerableTemplates
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing ADCS vulnerabilities: $_" -Color Red
        return $null
    }
}

function Get-CloudIdentityIntegrationAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "CLOUD IDENTITY INTEGRATION AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing cloud identity integration via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        
        # PTA (Pass-Through Authentication) Agent accounts
        $PTAPatterns = @("*PTA*", "*PassThrough*", "*AAD*", "*AzureAD*")
        $PTAAccounts = @()
        
        foreach ($Pattern in $PTAPatterns) {
            $Filter = "(sAMAccountName=$Pattern)"
            $Accounts = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "sAMAccountName", "memberOf", "description") -DC $DC -Cred $Cred
            if ($Accounts) {
                $PTAAccounts += $Accounts
            }
        }
        
        if ($PTAAccounts.Count -gt 0) {
            Write-ColorOutput "  [+] Found $($PTAAccounts.Count) potential PTA/SSO accounts" -Color Green
            Write-Host ""
            
            foreach ($Account in $PTAAccounts) {
                if ($Account.memberOf) {
                    $MemberOf = if ($Account.memberOf -is [array]) { $Account.memberOf } else { @($Account.memberOf) }
                    foreach ($GroupDN in $MemberOf) {
                        if ($GroupDN -like "*Domain Admins*" -or $GroupDN -like "*Enterprise Admins*") {
                            $Findings += @{
                                Title = "PTA/SSO Account in Admin Group"
                                Severity = "CRITICAL"
                                Description = "PTA/SSO account $($Account.sAMAccountName) is in admin group"
                                Details = "PTA/SSO accounts should not be in admin groups"
                            }
                            break
                        }
                    }
                }
            }
        } else {
            Write-ColorOutput "  [+] No PTA/SSO accounts detected" -Color Green
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            PTAAccounts = $PTAAccounts
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing cloud identity integration: $_" -Color Red
        return $null
    }
}

function Get-PAWHygieneAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "PRIVILEGED ACCESS WORKSTATION (PAW) HYGIENE AUDIT"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing PAW hygiene..." -Color Cyan
        
        Write-ColorOutput "  [*] PAW hygiene analysis requires event log analysis" -Color Yellow
        Write-ColorOutput "  [*] Check for:" -Color Cyan
        Write-ColorOutput "      - Tier0 accounts logging in from non-PAWs" -Color Gray
        Write-ColorOutput "      - Privileged accounts on shared workstations" -Color Gray
        Write-ColorOutput "      - Domain controllers used as jumpboxes" -Color Gray
        Write-ColorOutput "      - Admin tokens on untrusted machines" -Color Gray
        Write-Host ""
        
        # Get Tier0 groups for reference
        $DomainDN = Get-DomainDN -Domain $Domain
        $Tier0Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        $Tier0Members = @()
        
        foreach ($GroupName in $Tier0Groups) {
            $Filter = "(sAMAccountName=$GroupName)"
            $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName") -DC $DC -Cred $Cred
            if ($Group -and $Group.Count -gt 0) {
                $Members = Resolve-GroupMembership -GroupDN $Group[0].distinguishedName -DC $DC -Cred $Cred
                $Tier0Members += $Members
            }
        }
        
        Write-ColorOutput "  [*] Found $($Tier0Members.Count) Tier0 members (check their login sources)" -Color Yellow
        
        $Findings += @{
            Title = "PAW Hygiene Analysis"
            Severity = "INFO"
            Description = "PAW hygiene requires event log analysis to detect Tier0 logins from non-PAWs"
            Details = "Analyze Security event logs (Event ID 4624) for Tier0 account logins from non-PAW workstations"
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            Tier0Members = $Tier0Members
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing PAW hygiene: $_" -Color Red
        return $null
    }
}

function Get-DuplicateAccountsDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "DUPLICATE ACCOUNTS DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting duplicate accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(objectClass=user)(objectCategory=person))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "userPrincipalName", "name")
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        # Check for duplicate samAccountNames (shouldn't happen, but check)
        $SamAccountNames = $Users | Group-Object -Property sAMAccountName
        $DuplicateSamAccounts = $SamAccountNames | Where-Object { $_.Count -gt 1 }
        
        # Check for duplicate UPNs
        $UPNs = $Users | Where-Object { $_.userPrincipalName } | Group-Object -Property userPrincipalName
        $DuplicateUPNs = $UPNs | Where-Object { $_.Count -gt 1 }
        
        if ($DuplicateSamAccounts.Count -gt 0) {
            $Findings += @{
                Title = "Duplicate samAccountNames Detected"
                Severity = "CRITICAL"
                Description = "$($DuplicateSamAccounts.Count) duplicate samAccountNames found (should not exist)"
                Details = ($DuplicateSamAccounts | ForEach-Object { "$($_.Name): $($_.Count) accounts" })
            }
        }
        
        if ($DuplicateUPNs.Count -gt 0) {
            $Findings += @{
                Title = "Duplicate User Principal Names (UPNs)"
                Severity = "HIGH"
                Description = "$($DuplicateUPNs.Count) duplicate UPNs found"
                Details = ($DuplicateUPNs | Select-Object -First 20 | ForEach-Object { "$($_.Name): $($_.Count) accounts" })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        if ($Findings.Count -eq 0) {
            Write-ColorOutput "  [+] No duplicate accounts detected" -Color Green
        }
        
        return @{
            DuplicateSamAccounts = $DuplicateSamAccounts
            DuplicateUPNs = $DuplicateUPNs
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting duplicate accounts: $_" -Color Red
        return $null
    }
}

function Get-ExpiredAccountDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "EXPIRED ACCOUNT DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting expired accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(&(objectClass=user)(objectCategory=person))"
        
        $Properties = @("distinguishedName", "sAMAccountName", "accountExpires", "userAccountControl")
        $Users = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        $ExpiredAccounts = @()
        foreach ($User in $Users) {
            $UAC = if ($User.userAccountControl) { [int]$User.userAccountControl } else { 0 }
            $Enabled = ($UAC -band 0x0002) -eq 0
            
            if ($User.accountExpires -and $Enabled) {
                try {
                    $AccountExpires = [DateTime]::FromFileTime([int64]$User.accountExpires)
                    if ($AccountExpires -lt (Get-Date) -and $AccountExpires -ne [DateTime]::MaxValue) {
                        $ExpiredAccounts += $User
                    }
                } catch { }
            }
        }
        
        if ($ExpiredAccounts.Count -gt 0) {
            $Findings += @{
                Title = "Expired Accounts Still Enabled"
                Severity = "MEDIUM"
                Description = "$($ExpiredAccounts.Count) accounts have expired but are still enabled"
                Details = ($ExpiredAccounts | Select-Object -First 20 | ForEach-Object { "$($_.sAMAccountName) - Expired: $($_.accountExpires)" })
            }
        } else {
            Write-ColorOutput "  [+] No expired enabled accounts detected" -Color Green
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            ExpiredAccounts = $ExpiredAccounts
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting expired accounts: $_" -Color Red
        return $null
    }
}

function Get-InactiveAdminDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "INACTIVE ADMIN ACCOUNT DETECTION"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Detecting inactive admin accounts via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $AdminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        $AllAdmins = @()
        
        foreach ($GroupName in $AdminGroups) {
            $Filter = "(sAMAccountName=$GroupName)"
            $Group = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName") -DC $DC -Cred $Cred
            if ($Group -and $Group.Count -gt 0) {
                $Members = Resolve-GroupMembership -GroupDN $Group[0].distinguishedName -DC $DC -Cred $Cred
                $AllAdmins += $Members
            }
        }
        
        $AllAdmins = $AllAdmins | Select-Object -Unique
        
        if ($AllAdmins.Count -gt 0) {
            # Get admin user objects
            $AdminUserDNs = $AllAdmins | Where-Object { $_ -like "CN=*,*" }
            $InactiveAdmins = @()
            $NeverLoggedOnAdmins = @()
            
            foreach ($AdminDN in $AdminUserDNs) {
                $Filter = "(distinguishedName=$($AdminDN -replace '\(', '\28' -replace '\)', '\29'))"
                $AdminUser = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties @("distinguishedName", "sAMAccountName", "lastLogonTimestamp", "userAccountControl") -DC $DC -Cred $Cred
                
                if ($AdminUser -and $AdminUser.Count -gt 0) {
                    $UAC = if ($AdminUser[0].userAccountControl) { [int]$AdminUser[0].userAccountControl } else { 0 }
                    $Enabled = ($UAC -band 0x0002) -eq 0
                    
                    if ($Enabled) {
                        if ($AdminUser[0].lastLogonTimestamp) {
                            try {
                                $LastLogon = [DateTime]::FromFileTime([int64]$AdminUser[0].lastLogonTimestamp)
                                $DaysSince = (New-TimeSpan -Start $LastLogon -End (Get-Date)).Days
                                if ($DaysSince -gt 90) {
                                    $InactiveAdmins += $AdminUser[0]
                                }
                            } catch { }
                        } else {
                            $NeverLoggedOnAdmins += $AdminUser[0]
                        }
                    }
                }
            }
            
            if ($InactiveAdmins.Count -gt 0) {
                $Findings += @{
                    Title = "Inactive Admin Accounts (>90 days)"
                    Severity = "HIGH"
                    Description = "$($InactiveAdmins.Count) admin accounts have not logged on in 90+ days"
                    Details = ($InactiveAdmins | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
                }
            }
            
            if ($NeverLoggedOnAdmins.Count -gt 0) {
                $Findings += @{
                    Title = "Admin Accounts That Have Never Logged On"
                    Severity = "MEDIUM"
                    Description = "$($NeverLoggedOnAdmins.Count) admin accounts have never logged on"
                    Details = ($NeverLoggedOnAdmins | Select-Object -First 20 | ForEach-Object { $_.sAMAccountName })
                }
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            InactiveAdmins = $InactiveAdmins
            NeverLoggedOnAdmins = $NeverLoggedOnAdmins
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error detecting inactive admin accounts: $_" -Color Red
        return $null
    }
}

function Get-ComputerAccountPasswordDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "COMPUTER ACCOUNT PASSWORD ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing computer account passwords via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=computer)"
        
        $Properties = @("distinguishedName", "name", "pwdLastSet", "userAccountControl")
        $Computers = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        $OldComputerPasswords = @()
        $NeverChangedComputerPasswords = @()
        
        foreach ($Computer in $Computers) {
            $UAC = if ($Computer.userAccountControl) { [int]$Computer.userAccountControl } else { 0 }
            $Enabled = ($UAC -band 0x0002) -eq 0
            
            if ($Enabled) {
                if ($Computer.pwdLastSet) {
                    try {
                        $PwdLastSet = [DateTime]::FromFileTime([int64]$Computer.pwdLastSet)
                        $DaysSince = (New-TimeSpan -Start $PwdLastSet -End (Get-Date)).Days
                        if ($DaysSince -gt 90) {
                            $OldComputerPasswords += $Computer
                        }
                    } catch { }
                } else {
                    $NeverChangedComputerPasswords += $Computer
                }
            }
        }
        
        if ($OldComputerPasswords.Count -gt 0) {
            $Findings += @{
                Title = "Computer Accounts with Old Passwords (>90 days)"
                Severity = "MEDIUM"
                Description = "$($OldComputerPasswords.Count) computer accounts have passwords older than 90 days (should change every 30 days)"
                Details = ($OldComputerPasswords | Select-Object -First 20 | ForEach-Object { "$($_.name) - Last changed: $($_.pwdLastSet)" })
            }
        }
        
        if ($NeverChangedComputerPasswords.Count -gt 0) {
            $Findings += @{
                Title = "Computer Accounts with Passwords Never Changed"
                Severity = "MEDIUM"
                Description = "$($NeverChangedComputerPasswords.Count) computer accounts have never changed passwords"
                Details = ($NeverChangedComputerPasswords | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            OldComputerPasswords = $OldComputerPasswords
            NeverChangedComputerPasswords = $NeverChangedComputerPasswords
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing computer account passwords: $_" -Color Red
        return $null
    }
}

function Get-OUSecurityDetailedAudit {
    param([string]$Domain, [string]$DC, [System.Management.Automation.PSCredential]$Cred)
    
    Write-SectionHeader "OU SECURITY ANALYSIS"
    
    $Findings = @()
    
    try {
        Write-ColorOutput "  [*] Analyzing OU security via LDAP..." -Color Cyan
        
        $DomainDN = Get-DomainDN -Domain $Domain
        $Filter = "(objectClass=organizationalUnit)"
        
        $Properties = @("distinguishedName", "name", "nTSecurityDescriptor", "gPOptions")
        $OUs = Invoke-LDAPQuery -SearchBase $DomainDN -LDAPFilter $Filter -Properties $Properties -DC $DC -Cred $Cred
        
        $UnprotectedOUs = @()
        $BlockedInheritance = @()
        
        foreach ($OU in $OUs) {
            # Check for blocked inheritance (gPOptions = 1)
            if ($OU.gPOptions -and [int]$OU.gPOptions -eq 1) {
                $BlockedInheritance += $OU
            }
            
            # Check ACLs for protection
            if ($OU.nTSecurityDescriptor) {
                try {
                    $SDObj = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $SDObj.SetSecurityDescriptorBinaryForm($OU.nTSecurityDescriptor)
                    $SDDL = $SDObj.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    # Check for ProtectedFromAccidentalDeletion (simplified - would need full SDDL parsing)
                } catch { }
            }
        }
        
        if ($BlockedInheritance.Count -gt 0) {
            $Findings += @{
                Title = "OUs with Blocked GPO Inheritance"
                Severity = "LOW"
                Description = "$($BlockedInheritance.Count) OUs have blocked GPO inheritance"
                Details = ($BlockedInheritance | Select-Object -First 20 | ForEach-Object { $_.name })
            }
        }
        
        # Display findings
        foreach ($Finding in $Findings) {
            Write-Finding -Title $Finding.Title -Severity $Finding.Severity -Description $Finding.Description -Details $Finding.Details
        }
        
        return @{
            UnprotectedOUs = $UnprotectedOUs
            BlockedInheritance = $BlockedInheritance
            Findings = $Findings
        }
        
    } catch {
        Write-ColorOutput "  [!] Error analyzing OU security: $_" -Color Red
        return $null
    }
}

#endregion

#region Main Execution

function Main {
    Clear-Host
    Write-Host ""
    Write-Host ""
    
    # ASCII Art Banner - Kikoku
    Write-Host ""
    Write-Host "        ██╗  ██╗██╗██╗  ██╗ ██████╗ ██╗  ██╗██╗   ██╗" -ForegroundColor Cyan
    Write-Host "        ██║ ██╔╝██║██║ ██╔╝██╔═══██╗██║ ██╔╝██║   ██║" -ForegroundColor Cyan
    Write-Host "        █████╔╝ ██║█████╔╝ ██║   ██║█████╔╝ ██║   ██║" -ForegroundColor Cyan
    Write-Host "        ██╔═██╗ ██║██╔═██╗ ██║   ██║██╔═██╗ ██║   ██║" -ForegroundColor Cyan
    Write-Host "        ██║  ██╗██║██║  ██╗╚██████╔╝██║  ██╗╚██████╔╝" -ForegroundColor Cyan
    Write-Host "        ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "    ║          ADVANCED ACTIVE DIRECTORY SECURITY AUDIT TOOL           ║" -ForegroundColor Magenta
    Write-Host "    ║                    STANDALONE EDITION v2.0                      ║" -ForegroundColor Magenta
    Write-Host "    ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "    Creator: " -NoNewline -ForegroundColor White
    Write-Host "4vian" -ForegroundColor Yellow -NoNewline
    Write-Host " | " -NoNewline -ForegroundColor Gray
    Write-Host "Version: " -NoNewline -ForegroundColor White
    Write-Host "2.0" -ForegroundColor Green
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [!] " -NoNewline -ForegroundColor Yellow
    Write-Host "AUTHORIZED USE ONLY - For legitimate security audits" -ForegroundColor White
    Write-Host "    [*] " -NoNewline -ForegroundColor Green
    Write-Host "Standalone: NO ActiveDirectory PowerShell module required" -ForegroundColor White
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $StartTime = Get-Date
    $AllFindings = @()
    
    # Domain Information
    $DomainInfo = Get-DomainAuditInfo -Domain $Domain -DC $DomainController -Cred $Credential
    
    # User Audit
    $UserAudit = Get-UserAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($UserAudit) {
        $AllFindings += $UserAudit.Findings
    }
    
    # ACL Abuse Path Analysis (BloodHound-style)
    $ACLAudit = Find-ACLAbusePaths -DC $DomainController -Cred $Credential
    if ($ACLAudit) {
        $AllFindings += $ACLAudit.Findings
    }
    
    # Group Audit
    $GroupAudit = Get-GroupAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($GroupAudit) {
        $AllFindings += $GroupAudit.Findings
    }
    
    # Computer Audit
    $ComputerAudit = Get-ComputerAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ComputerAudit) {
        $AllFindings += $ComputerAudit.Findings
    }
    
    # Password Policy Audit
    $PasswordPolicyAudit = Get-PasswordPolicyAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($PasswordPolicyAudit) {
        $AllFindings += $PasswordPolicyAudit.Findings
    }
    
    # Trust Audit
    $TrustAudit = Get-TrustAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($TrustAudit) {
        $AllFindings += $TrustAudit.Findings
    }
    
    # Delegation Audit
    $DelegationAudit = Get-DelegationAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($DelegationAudit) {
        $AllFindings += $DelegationAudit.Findings
    }
    
    # Kerberoastable Detection
    $KerberoastableAudit = Get-KerberoastableAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($KerberoastableAudit) {
        $AllFindings += $KerberoastableAudit.Findings
    }
    
    # AS-REP Roastable Detection
    $ASREPRoastableAudit = Get-ASREPRoastableAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ASREPRoastableAudit) {
        $AllFindings += $ASREPRoastableAudit.Findings
    }
    
    # Shadow Admins Detection
    $ShadowAdminsAudit = Get-ShadowAdminsAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ShadowAdminsAudit) {
        $AllFindings += $ShadowAdminsAudit.Findings
    }
    
    # User Attribute Analysis
    $UserAttributeAudit = Get-UserAttributeAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($UserAttributeAudit) {
        $AllFindings += $UserAttributeAudit.Findings
    }
    
    # Service Account Audit
    $ServiceAccountAudit = Get-ServiceAccountAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ServiceAccountAudit) {
        $AllFindings += $ServiceAccountAudit.Findings
    }
    
    # GPO Audit
    $GPOAudit = Get-GPOAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($GPOAudit) {
        $AllFindings += $GPOAudit.Findings
    }
    
    # OU Audit
    $OUAudit = Get-OUAudit -Domain $Domain -DC $DomainController -Cred $Credential
    
    # Protected Users Audit
    $ProtectedUsersAudit = Get-ProtectedUsersAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ProtectedUsersAudit) {
        $AllFindings += $ProtectedUsersAudit.Findings
    }
    
    # AdminSDHolder Audit
    $AdminSDHolderAudit = Get-AdminSDHolderAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($AdminSDHolderAudit) {
        $AllFindings += $AdminSDHolderAudit.Findings
    }
    
    # ADCS Audit
    $ADCSAudit = Get-ADCSAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ADCSAudit) {
        $AllFindings += $ADCSAudit.Findings
    }
    
    # GPP Password Detection
    $GPPPasswordAudit = Get-GPPPasswordAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($GPPPasswordAudit) {
        $AllFindings += $GPPPasswordAudit.Findings
    }
    
    # LAPS Audit
    $LAPSAudit = Get-LAPSAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($LAPSAudit) {
        $AllFindings += $LAPSAudit.Findings
    }
    
    # gMSA Audit
    $gMSAAudit = Get-gMSAAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($gMSAAudit) {
        $AllFindings += $gMSAAudit.Findings
    }
    
    # DCSync Rights Audit
    $DCSyncRightsAudit = Get-DCSyncRightsAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($DCSyncRightsAudit) {
        $AllFindings += $DCSyncRightsAudit.Findings
    }
    
    # Exchange Server Detection
    $ExchangeServerAudit = Get-ExchangeServerAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ExchangeServerAudit) {
        $AllFindings += $ExchangeServerAudit.Findings
    }
    
    # Outdated OS Detection
    $OutdatedOSAudit = Get-OutdatedOSAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($OutdatedOSAudit) {
        $AllFindings += $OutdatedOSAudit.Findings
    }
    
    # Azure AD Connect Detection
    $AzureADConnectAudit = Get-AzureADConnectAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($AzureADConnectAudit) {
        $AllFindings += $AzureADConnectAudit.Findings
    }
    
    # Advanced Security Features
    $SYSVOLGPOScriptAudit = Get-SYSVOLGPOScriptAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($SYSVOLGPOScriptAudit) {
        $AllFindings += $SYSVOLGPOScriptAudit.Findings
    }
    
    $GPODelegationAudit = Get-GPODelegationAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($GPODelegationAudit) {
        $AllFindings += $GPODelegationAudit.Findings
    }
    
    $TieredAdminAudit = Get-TieredAdministrationAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($TieredAdminAudit) {
        $AllFindings += $TieredAdminAudit.Findings
    }
    
    $LDAPHardeningAudit = Get-LDAPHardeningAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($LDAPHardeningAudit) {
        $AllFindings += $LDAPHardeningAudit.Findings
    }
    
    $KerberosHardeningAudit = Get-KerberosHardeningAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($KerberosHardeningAudit) {
        $AllFindings += $KerberosHardeningAudit.Findings
    }
    
    $SMBShareAudit = Get-SMBShareAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($SMBShareAudit) {
        $AllFindings += $SMBShareAudit.Findings
    }
    
    $gMSAPasswordAudit = Get-gMSAPasswordRetrievalAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($gMSAPasswordAudit) {
        $AllFindings += $gMSAPasswordAudit.Findings
    }
    
    $DCSyncShadowAudit = Get-DCSyncShadowPermissionsAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($DCSyncShadowAudit) {
        $AllFindings += $DCSyncShadowAudit.Findings
    }
    
    $ExchangeHybridAudit = Get-ExchangeHybridAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ExchangeHybridAudit) {
        $AllFindings += $ExchangeHybridAudit.Findings
    }
    
    $FSMORolesAudit = Get-FSMORolesAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($FSMORolesAudit) {
        $AllFindings += $FSMORolesAudit.Findings
    }
    
    $DNSMisconfigAudit = Get-DNSMisconfigurationAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($DNSMisconfigAudit) {
        $AllFindings += $DNSMisconfigAudit.Findings
    }
    
    $SitesSubnetsDetailedAudit = Get-SitesSubnetsDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($SitesSubnetsDetailedAudit) {
        $AllFindings += $SitesSubnetsDetailedAudit.Findings
    }
    
    $FGPPDetailedAudit = Get-FGPPDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($FGPPDetailedAudit) {
        $AllFindings += $FGPPDetailedAudit.Findings
    }
    
    $RODCDetailedAudit = Get-RODCDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($RODCDetailedAudit) {
        $AllFindings += $RODCDetailedAudit.Findings
    }
    
    $SPNHygieneAudit = Get-SPNHygieneAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($SPNHygieneAudit) {
        $AllFindings += $SPNHygieneAudit.Findings
    }
    
    $AccountLockoutDetailedAudit = Get-AccountLockoutPolicyDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($AccountLockoutDetailedAudit) {
        $AllFindings += $AccountLockoutDetailedAudit.Findings
    }
    
    $NetlogonCryptoAudit = Get-NetlogonCryptoAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($NetlogonCryptoAudit) {
        $AllFindings += $NetlogonCryptoAudit.Findings
    }
    
    $SCCMAudit = Get-SCCMAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($SCCMAudit) {
        $AllFindings += $SCCMAudit.Findings
    }
    
    $StaleObjectAudit = Get-StaleObjectAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($StaleObjectAudit) {
        $AllFindings += $StaleObjectAudit.Findings
    }
    
    $ADCSVulnerabilityAudit = Get-ADCSVulnerabilityAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ADCSVulnerabilityAudit) {
        $AllFindings += $ADCSVulnerabilityAudit.Findings
    }
    
    $CloudIdentityAudit = Get-CloudIdentityIntegrationAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($CloudIdentityAudit) {
        $AllFindings += $CloudIdentityAudit.Findings
    }
    
    $PAWHygieneAudit = Get-PAWHygieneAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($PAWHygieneAudit) {
        $AllFindings += $PAWHygieneAudit.Findings
    }
    
    $DuplicateAccountsAudit = Get-DuplicateAccountsDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($DuplicateAccountsAudit) {
        $AllFindings += $DuplicateAccountsAudit.Findings
    }
    
    $ExpiredAccountAudit = Get-ExpiredAccountDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ExpiredAccountAudit) {
        $AllFindings += $ExpiredAccountAudit.Findings
    }
    
    $InactiveAdminAudit = Get-InactiveAdminDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($InactiveAdminAudit) {
        $AllFindings += $InactiveAdminAudit.Findings
    }
    
    $ComputerAccountPasswordAudit = Get-ComputerAccountPasswordDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($ComputerAccountPasswordAudit) {
        $AllFindings += $ComputerAccountPasswordAudit.Findings
    }
    
    $OUSecurityAudit = Get-OUSecurityDetailedAudit -Domain $Domain -DC $DomainController -Cred $Credential
    if ($OUSecurityAudit) {
        $AllFindings += $OUSecurityAudit.Findings
    }
    
    # Summary
    Write-SummaryReport -AllFindings $AllFindings
    
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "Audit completed in " -NoNewline -ForegroundColor Cyan
    Write-Host "$([math]::Round($Duration.TotalSeconds, 2)) seconds" -ForegroundColor White
    Write-Host ""
    Write-Host "    " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "Standalone version - No ActiveDirectory module required" -ForegroundColor White
    Write-Host "    " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "All queries performed via raw LDAP" -ForegroundColor White
    Write-Host ""
    Write-Host "    " -NoNewline
    Write-Host "Creator: " -NoNewline -ForegroundColor Gray
    Write-Host "4vian" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ""
}

# Run main function
try {
    Main
} catch {
    Write-Error "Fatal error: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
}

#endregion
