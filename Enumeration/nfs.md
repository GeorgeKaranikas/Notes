- TCP Ports 111/2049


# NFS 

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same 
purpose as SMB. Its purpose is to access file systems over a network as if they were local. 
However, it uses an entirely different protocol. NFS is used between Linux and Unix systems. 
This means that NFS clients cannot communicate directly with SMB servers. 
NFS is an Internet standard that governs the procedures in a distributed file system.The NFS protocol has no mechanism for authentication or authorization. Instead, authentication is completely shifted to the RPC protocol's options. T

# NFS Configuration 

`/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients

    
# NFS Enum 
            
`$ sudo nmap -sV -sC -p 111,2049 x.x.x.x`
        
        (will propably use rpcinfo nse script)
        you can also use the --script nfs* switch

# Show Available NFS Shares

`$ showmount -e x.x.x.x`

# Mounting NFS Share

```            
$ mkdir local_dir
$ sudo mount -t {target_nfs} x.x.x.x:/ ./{local_dir}/ -o nolock
```

There we will have the opportunity to access the rights and the usernames and groups to whom the shown and viewable files belong. Because once we have the usernames, group names, UIDs, and GUIDs, we can create them on our system and adapt them to the NFS share to view and modify the files.


    !!It is important to note that if the root_squash option is set, we cannot edit the files with 0 uid/gid even as root.


# Unmount
    
`$ sudo umount ./target-NFS`


