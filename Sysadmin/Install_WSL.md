# WSL Install

- Enable Virtualization from BIOS

- Run:

```powershell
PS> wsl --install

PS> DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V

PS> bcdedit /set hypervisorlaunchtype auto
```

- Find `ubuntu` in startup menu and fire it up

-  It mounts the file systems of your Windows under the /mnt/ directory
    - Run `ls /mnt/c`
