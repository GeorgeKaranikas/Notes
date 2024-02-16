                    -----Windows Defender

     
        \\\Checking the Status of Defender with Get-MpComputerStatus

     by default, will block tools such as PowerView

     We can use the built-in PowerShell cmdlet Get-MpComputerStatus to get the current Defender status.


      RealTimeProtectionEnabled parameter is set to True, which means Defender is enabled on the system.


                    ------AppLocker


        An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. 

         It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.

        Organizations also often focus on blocking the PowerShell.exe executable, but forget about the other PowerShell executable locations such as %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe or PowerShell_ISE.exe. 


        \\\Using Get-AppLockerPolicy cmdlet

        PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections



                    -----PowerShell Constrained Language Mode


        PowerShell Constrained Language Mode locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more. We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.

        PS C:\htb> $ExecutionContext.SessionState.LanguageMode


        
                        ----LAPS
        
        The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement. 

        Enumeration may show a user account that can read the LAPS password on a host. This can help us target specific AD users who can read LAPS passwords.

            \\\\Using Find-LAPSDelegatedGroups
        
        PS C:\htb> Find-LAPSDelegatedGroups


            \\\\Using Find-AdmPwdExtendedRights

        The Find-AdmPwdExtendedRights checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.


        PS C:\htb> Find-AdmPwdExtendedRights


            \\\Using Get-LAPSComputers

        We can use the Get-LAPSComputers function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.

        PS C:\htb> Get-LAPSComputers

        
