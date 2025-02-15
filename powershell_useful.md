# List available modules

```
PS C:\htb> Get-Module -ListAvailable 
```


# Credentials in Powershell

```
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
```





# Connect to smb share with PS Credentials

```
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

                    

# Connect without Credentials

```
PS C:\> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

            

# Count the files in an smb drive

```

    dir n: /a-d /s /b | find /c ":\"

    dir 	        Application
    n: 	        Directory or drive to search
    /a-d 	    /a is the attribute and -d means not directories
    /s 	        Displays files in a specified directory and all subdirectories
    /b 	        Uses bare format (no heading information or summary)
```


#  Search in smb with a pattern in filename

```
C:\htb>dir n:\*cred* /s /b

PS > Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```


# Search for text patterns in smb files

```    
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

    

# Search for a specific string in all files in a directory
  
``` 
PS > ls directory\ -recurse | Select-String "string" | Select Path, LineNumber | Format-List
```


		
# Ping sweep
```
PS> 1..254| % {"172.16.5.$($_) : $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet"} 
```


# PowerShell Base64 Encode & Decode

```
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

```

