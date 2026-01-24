[Practical Linux Forensics
A Guide for Digital Investigators: Appendix](https://digitalforensics.ch/linux/practical-linux-forensics-appendix-2021-07-17.pdf)



# Linux Persistence

- User Session Strartuo Scripts
    - ~/.xprofile
- Service Management tools
    - chkconfig etc.
- Shell Profile Files
    - ~/.bashrc , ~/.bash_profile , ~/.profile
- /etc/rc.local
    - /etc/rc* are symlinked to systemd
- Startup apps
    - Gnome (~/.config/) , KDE etc.
- SSH Keys
    - ~/.ssh/authorized_keys
- Cronjobs
    - /etc/crontab ($crontab -l)
- Systemd
    - /lib/systemd/system/ , /etc/systemd/system/
- Init scripts
    - /etc/init.d





# Network Forensics

# Usefull files

- /proc/net/arp
- /proc/net/*
- /var/log/wtmp
    - You can check for ssh access ,logins ,etc.
    - accessed with last command
- /var/log/auth.log
### Memory Dump

- Finding sockets with Volatility

```bash
$ python3 vol.py -q -f memdump.mem linux.sockstat.Sockstat | grep TCP
```



# Linux Processes

# Usefull Files

- /etc/sudoers
    - If you notice suspicious modification, check with stat command to verify
- /var/log/apt/history.log

### Find rwx permissions in processes

```bash
$ python3 volatility3.py -q -f /home/web-server-dump linux.malfind.Malfind --pid {pid}
```

### Check executed commands and process relationships (pid-ppid)

```bash
$ python3 volatility3.py -q -f /home/web-server-dump linux.psaux.PsAux
```


### Create dumps from processes

```bash
$ python3 volatility3.py -q -f /home/dump.mem linux.proc.Maps --dump --pid {pid1 pid2 ...}
```


### Check for Enviromental variables

- once youve found potentially malicious processes , check for env`s

```bash
python3 vol.py -q -f /home/dump.mem linux.envvars --pid {pid}
```

# Bash History 

### In-memory history 

```bash
$ python3 volatility3.py -q -f /home/dump.mem linux.bash.Bash
```

# Access and modified files

-search for files in a specific range of time

```bash
$ find /folder/to/files -type f -newermt "2026-01-01 00:00:00"
```