[SANS blog](https://www.sans.org/blog/working-with-event-log-part-1/)


## Usefull 

-  Most of the Get-WinEvent commands will require an administrative powershell session.
 
### Event ID`s

#### Processes

- Event ID 106 indicates a task creation
- Event ID 319 indicates that the task process has started
- Event ID 102 indicates that task execution has completed

- Event ID :4688 indicates process creation
	- disabled by default
	- Sysmon event ID 1

- Event ID: 7045 in the System event log indicates a new service
was created



#### Logons
- Event ID :4624 indicates a successful logon

  - Type 2 = Keyboard logon
  - Type 3 = Network logon (e.g. mapping a share)
  -  Type 10 = RDP logon
  - names ending in "$" are machine accounts
-  Event ID :4625 indicates a failed logon

   - Reason code 0xC0000234 indicates the account is currently locked out

- Event ID 4648 details attempts to log on as another user by
using explicit credentials
	- runas command
	- password spraying attacks
	- On the remote system, you only get to see the target account
used (4624/4625), but on the source system you can see both
the target account AND the source account

- Event ID :4672 indicates that special privileges
were assigned to a new logon

- Event ID :4720 indicates that a new account was created

- Event ID 4732 indicates that an account was
added to a local security group


#### Kerberos and domain

- Event ID :4768 indicates a TGT was issued (usually only issued at
logon time)

- Event ID :4769 indicates a Service Ticket was issued (TGS)

- Event IDs : 4728 and 4756 indicate that an account was added to
a domain group

- Event ID 5140 indicates that a share was accessed

	- shares ending with a "$" are not browsable


### Listing available Log Sources

```
PS > Get-WinEvent -ListLog *

PS > Get-WinEvent -ListLog * | Select-Object LogName , RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

```

```
PS > Get-WinEvent -ListLog * | Where-Object -Property RecordCount -GT 0 | Select-Object -Property LogName, RecordCount , IsEnabled, LogType
```
! isClassicLog refers to the file type.

True is . evt , while False is .evtx etc.


### List available providers

```
PS > Get-WinEvent -ListProvider * | Format-Table -AutoSize

```
### Retrieving events from the System log



```
PS > Get-WinEvent -LogName "System" -MaxEvents x | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

```

! To retrieve the oldest events, instead of manually sorting the results, we can utilize the -Oldest parameter

! To retrieve log entries from a .evtx file, you need to provide the log file's path using the -Path parameter. 


### Count Events


```
PS  > ( Get-WinEvent -LogName "System" ).Count

```

### Filtering events with FilterHashtable

```
PS > Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

```
! When using -FilterHashTable, you must specify a LogName in the hash table, not using the -LogName cmdlet argument.

|Key name |	Data type |	Wildcard Support|
|-----|--------|-------|
|Key name |	Data type 	|Wildcard Support|
|LogName |	<String[]>| 	Yes
|ProviderName 	|<String[]> |	Yes
|Path 	|<String[]> 	|No
|Keywords 	|<Long[]> 	|No
|ID 	|<Int32[]> |	No
|Level |	<Int32[]> |	No
|StartTime |	DateTime 	|No
|EndTime 	|DateTime |	No
|UserID |	SID	|No
|Data 	|<String[]> 	|No
|named-data |	<String[]> 	|No|


### Events in time range

```
PS > $startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date

PS > $endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date

 PS > Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```



### Filter for Event Properties

```
PS C:\Windows\system32> Get-WinEvent -LogName Security | Where-Object -Property Id -EQ 1102 | Format-List -Property TimeCreated,Message
```





### unauthorized access attempts

```

PS > Get-WinEvent -FilterHashTable @{ LogName = 'Security'; Id=4624,4634,4672,4732,4648,4688,4768 } | Format-List
```

### Filter Critical Severity level

```

PS > Get-WinEvent -FilterHashTable @{ LogName = 'System'; Level = 1 } |Format-List

```

### Changes to the Windows Firewall

```
PS > Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Id=2004,2006 } | Format-List
```


### Hunt for Powershell Base64 Strings

```
PS > Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | Where-object -Property Message -Match "[A-Za-z0-9+/=]{200}" | Format-List -Property Message
```


### Filter for Username With FilterXPath

```

PS > Get-WinEvent -LogName Security -FilterXPath "*[EventData[Data[@Name='TargetUserName']='assetmgr']]" | Select-Object TimeCreated, Id, Message

```

### Search for sysmon event ID with XML

```
PS > $Query = @"
	<QueryList>
		<Query Id="0">
			<Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
			</Select>
		</Query>
	</QueryList>
	"@
```

```
PS > Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
```

### Filter for Properties (Message NoteProperty)

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List



```
!Thats ParrentCommandLine based on EventData(Message NoteProperty) on a sysmon event which translates 
in "Properties" property in event`s powershell class


### Access Message NoteProperty with XML

```

PS > $logonEvent = Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } -MaxEvents 1

PS > $xml = $logonEvent.ToXml()

PS > $xml.Event.EventData.Data

```

### Access Message NoteProperty Using Cnvert-EventLogRecord

[Conver-EventLogReader](https://github.com/jdhitsolutions/PSScriptTools/blob/master/functions/Convert-EventLogRecord.ps1)

```
PS > Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } | Convert-EventLogRecord | Where-Object -Property TargetUserName -E 'SYSTEM' | Select-Object TargetUsername, TimeCreated, LogonType

```