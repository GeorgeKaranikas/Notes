# General

### Registry key values

```powershell
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"

Get-ItemProperty -Path $path

$sub = "DisabledComponents"

Get-ItemProperty -Path $path -Name $sub 
```

### Modify Registry values

```powershell
PS C:\> Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF
```




# Blue_team

### Disable dsHeuristics LDAP Attribute - Disable Ldap anonymous Bind
[msdn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b)

```powershell
# Obtain domain name, build LDAP path to the Directory Service object, connect as an ADSI object
$Dcname = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
$Adsi = 'LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' + $Dcname
$AnonADSI = [ADSI]$Adsi

# Clear the dSHeuristics attribute 
$AnonADSI.Properties["dSHeuristics"].Clear()
$AnonADSI.SetInfo()
```


### Remove Dangerous Read Permissions From CN=Users 

```powershell
# Remove ANONYMOUS LOGON read access on CN=Users
$ADSI = [ADSI]('LDAP://CN=Users,' + $Dcname)
$Anon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
$SID = $Anon.Translate([System.Security.Principal.SecurityIdentifier])
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,$adRights,$type,$inheritanceType
$ADSI.PSBase.ObjectSecurity.RemoveAccessRule($ace) | Out-Null
$ADSI.PSBase.CommitChanges()
```




