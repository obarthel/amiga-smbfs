# A SMB file system wrapper for AmigaOS, using the AmiTCP V3 API

## 1. What is it?

This document describes the **smbfs** program, which implements an *SMB* file system for AmigaOS.

This file system can be used to access files made available by file servers which implement the *SMBv1* protocol (*SMBv1* is also called *CIFS*, which stands for *Common Internet File System*), such as *Microsoft Windows* or any other platform which supports the free *Samba* product.

These files can be accessed using shell commands such as `List`, the *Workbench* or utilities such as *Directory Opus* as if the file server were a local disk drive.

You may find **smbfs** useful if you want to access a NAS (*network-attached storage*) drive, or even a Linux file server.


## 2. What do you need to get started?

You need a TCP/IP stack that supports the *AmiTCP V3* API, such as *Miami*, the original free *AmiTCP 3.0* release, *AmiTCP 4.x*, *Miami Deluxe*, *AmiTCP Genesis* or *Roadshow* and the obligatory networking gear. All these items need to be in good shape and properly configured.

Most important, you need a computer which offers file sharing services using the *SMBv1* protocol (instead of being referred to as *SMBv1*, it may be called *CIFS*, too).

It often helps to have *Samba* installed on your Amiga, too, as this can aid in tracking down bugs and obtaining information which **smbfs** cannot obtain all by itself.

Last but not least, you need to be proficient in configuring and using the TCP/IP stack; networking knowledge is definitely assumed.

The **smbfs** program requires *AmigaOS 2.04* or higher to work.


## 3. Preparations

You need to know which computer's files you want to share using the **smbfs** file system. That computer must be known by name or by its IPv4 address.

The name of the computer to connect to cannot be longer than 16 characters.

You need to know which service you want to connect to on the target computer. You can find out which services are available on a certain computer by using the Samba `smbclient` program.

For example, if you were to query the services offered by a machine called *sourcery* you could enter the following:

<pre>
samba:bin/smbclient -L sourcery
</pre>

And you might get the following information:

<pre>
added interface ip=192.168.0.1 bcast=192.168.0.255 nmask=255.255.255.0
Password: Domain=[ARBEITSGRUPPE] OS=[AmigaOS] Server=[Samba 2.0.7]

        Sharename      Type      Comment
        ---------      ----      -------
        All            Disk      All volumes in the system
        IPC$           IPC       IPC Service (Amiga 3000UX)
        olsen          Disk      Home Directories

        Server               Comment
        ---------            -------
        SOURCERY             Amiga 3000UX

        Workgroup            Master
        ---------            -------
        ARBEITSGRUPPE        SOURCERY
</pre>

The share name to connect to would be `ALL`.

You may need to know which login name and which password are required to connect to the shared disk.

Very rarely, you would need to know the name of the work group or domain which the file server is a member of. In the example above, the name of the domain would be `ARBEITSGRUPPE`.


## 4. Starting and stopping the file system

**smbfs** is an uncommon kind of file system in that you do not use the `Mount` command to mount it. In fact, **smbfs** is a program which can be launched from the shell, using command line parameters to tell it which disk should be used. But you can also start it from Workbench: in this case you would have to put the program's command line options into icon tool types.

Please note that if you start **smbfs** from Workbench, you will not be able to stop **smbfs** using the `Status` and `Break` shell commands.

### 4.1. Starting the file system

By now you should have prepared the following information:

* Name of the computer to connect to; this would be the file server
* Name of the shared disk to connect to
* Login name and password (optional)

That's basically everything you need to know to continue -- unless something goes wrong, but more on that later on.

Now you can start the file system. For example, to connect to the file server called *sourcery* and the shared *all* disk it provides, using the login name *PCGuest* and not providing any password, you would enter the following:

<pre>
smbfs user=PCGuest service=//sourcery/all
</pre>

This would cause a new device by the name of `SMBFS:` to be mounted, showing all files and drawers the *sourcery* server makes available for sharing.

You can also run the **smbfs** program in the background, like so:

<pre>
Run >NIL: smbfs user=PCGuest service=//sourcery/all`
</pre>

**Note that this is not recommended** because it becomes much harder to tell why the **smbfs** program did not work correctly (as it invariably will at some point). Any error messages which could help in figuring out what the problem may have been will be lost.

If you have trouble setting up the **smbfs** program, first make sure that it works correctly without the `Run >NIL:` instructions and have a look at any error messages it may produce.

### 4.2. Stopping the file system

How do you "unmount" the file system? Stopping the **smbfs** program will unmount the file system. This can be accomplished by either hitting the `[Ctrl]+C` keys or by using the `Status` shell command and then the `Break` command.

For example, the `Status` shell command may produce the following output:

<pre>
Process  1: Loaded as command: TURBOTEXT
Process  2: Loaded as command: Work:Tools/Blowup
Process  3: Loaded as command: Work:Tools/Sashimi
Process  4: Loaded as command: Work:CyberTools/CyberGuard
Process  5: Loaded as command: Work:Tools/OpenDevicePatch
Process  6: Loaded as command: CED
Process  7: Loaded as command: Workbench
Process  8: Loaded as command: Status
Process  9: No command loaded
Process 10: Loaded as command: SMBFS '//sourcery/all'
</pre>

Look at the last line describing process number 10: it shows the name of the file system program **smbfs** and the name of the *SMB* share it is connected to.

To stop this file system and effectively unmount it, use the shell `Break` command; in this case you would enter `Break 10` to stop the file system.

Note that the **smbfs** program may not quit immediately. It may have to wait until the last client has released all the resources it obtained from the file system.

You may have to send more than one `Break` command to stop the **smbfs** program.

### 4.3. Temporarily disabling the file system

If, for example, you need to temporarily shut down the network, **smbfs** will be unable to do its job, at least until the network becomes operational again. In the mean time *Workbench* and other programs will keep accessing the file system and may get stuck.

You can avoid most of these problems by temporarily disabling the file system until it can access the network again. For this to work, you need to start the **smbfs** program in the shell and use the `VOLUMENAME` option, which will make a disk icon appear in the *Workbench* window.

Please note that **smbfs** needs to have been started as a shell command rather than from Workbench to allow it to be temporarily disabled and then enabled again.

To disable the file system, hit the `[Ctrl]+D` keys or use the `Break` command (e.g. `Break 10 D` if **smbfs** is running as process number 10).

To re-enable the file system again, hit the `[Ctrl]+E` keys or use the `Break` command (e.g. `Break 10 E` if **smbfs** is running as process number 10).


## 5. Startup options

The **smbfs** program supports a number of options which control how it works.

You can enter these options as command line parameters, or, if you start the **smbfs** program from *Workbench*, you can set these options as icon tool types.

Here is how the options look like, in alphabetical order (as command line parameters):

<pre>
ADDVOLUME/K
CACHE=CACHESIZE/N/K
CACHETABLES/N/K
CASE=CASESENSITIVE/S
CHANGEUSERNAMECASE/K
CHANGEPASSWORDCASE/K
CHANGECASE/S
CLIENT=CLIENTNAME/K
CP437/S
CP850/S
DEBUGFILE/K
DEBUGLEVEL=DEBUG/N/K
DEVICE=DEVICENAME/K
DISABLEEXALL/S
DOMAIN=WORKGROUP/K
DST=DSTOFFSET/N/K
ERROROUTPUT/K
MAXNAMELEN/N/K
MAXTRANSMIT/N/K
NETBIOS/S
OMITHIDDEN/S
PASSWORD/K
PROTOCOL/K
QUIET/S
RAISEPRIORITY/S
READONLY/N/K
READTHRESHOLD/N/K
SERVER=SERVERNAME/K
SERVICE/A
SESSIONSETUP/K
SETENV/S
TIMEOUT/N/K
TRANSLATE=TRANSLATIONFILE/K
TZ=TIMEZONEOFFSET/N/K
UNICODE/K
USER=USERNAME/K
VOLUME=VOLUMENAME/K
WRITEBEHIND/S
WRITETHRESHOLD/N/K
</pre>

### 5.1. Server and authentication options

In order to use a shared networked file system, you need the following information:

1. The name or the IPv4 address of the file server and the name of the "share" (file system) you want to access.
2. The user name required to access the "share" (file system), unless the server does not need it ("guest" access).
3. The password required to access the "share" (file system), unless the server does not need it ("guest" access).

The parameters relevant for this information are described below.

#### 5.1.1. `SHARE=SERVICE/A`

This parameter takes the form of `//server-name/share-name` or `//server-name:port-number/share-name`. You can also use the SMB URI form
`smb://[[workgroup;]user-name[:password]@]server-name[:port-number]/share`.

For example `//sourcery/all`, `//192.168.0.1/all`, `//nas:445/files`, `//nas:microsoft-ds/files`, `smb://sourcery/all`, `smb://user@sourcery/all`
and `smb://user:password@sourcery/all` would all be valid `SHARE` parameters.

In this example `server-name` must be either the IPv4 address of the file server to connect to, or the name of the server (**note that server names cannot be longer than 16 characters**).

If necessary, you can specify which port number should be used when making the connection. The port number is optional, though. In place of the port (e.g. 445) number you can also use the name of a TCP/UDP service (e.g. `microsoft-ds`).

Finally, you need to tell the *SMB* server which service you want to connect to, which for the **smbfs** program should be the name of a shared network file system. In the example the name of the shared network file system would be `share-name`.

Unless you use the `VOLUMENAME` option (e.g. `VOLUMENAME=MyData`), **smbfs** will pick a volume name identical to the share name, e.g for `//nas:445/pictures` the volume name would be `pictures` and a disk icon named **pictures** will appear in the Workbench window.

#### 5.1.2. `USER=USERNAME/K`

In order to connect to an *SMB* share, the server requires that a user name is provided. If you omit the user name, the **smbfs** program will use `GUEST` as a replacement.

If you do provide a user name, **it must not be longer than 63 characters**. Unless you use the `CHANGEUSERNAMECASE=NO` option the name you provide will be translated to all upper case characters.

You need not provide for a user name on the command line. Alternatively, you may configure an environment variable whose contents will be used instead. The variable could be set up like this:

<pre>
SetEnv smbfs_username *your user name*
Copy ENV:smbfs_username ENVARC:
</pre>

You may also use the `smbfs_user` environment variable in place of the `smbfs_username` variable. The two are aliases for one another, but **smbfs** will read only one of the two.

#### 5.1.3. `PASSWORD/K`

You may not need to provide a password in order to connect to an *SMB* share. If you omit it, the **smbfs** program will use an empty password.

You need not provide for a password on the command line. Alternatively, you may configure an environment variable whose contents will be used instead. The variable could be set up like this:

<pre>
SetEnv smbfs_password *your password*
Copy ENV:smbfs_password ENVARC:
</pre>

Keep in mind that passwords like these really should not be exposed by storing them in environment variables. But then the protocol **smbfs** uses is almost as insecure as it gets anyway.

The authentication process only works if the machine you are connecting to knows about the user name and password you want to use. As of this writing, **smbfs** can only be used for authenticating against a password server that is the same machine as the one on which you wish to access a share.

#### 5.1.4. `CHANGEUSERNAMECASE/K`

Many file servers require that the user name is provided in all-upper-case characters or they will refuse to grant you access. This is why **smbfs** defaults to convert the user name to all-upper-case characters.

However, some file servers such as the **Solaris**/**OpenSolaris**/**OpenIndiana** SMB server require that the user name matches exactly and the conversion to all-upper-case characters will cause trouble.

In order to disable the user name case conversion use the `CHANGEUSERNAMECASE=NO` option. If you omit the `CHANGEUSERNAMECASE` option altogether it will default to `CHANGEUSERNAMECASE=YES`.

#### 5.1.5. `CHANGEPASSWORDCASE/K`

By default the password you provide with the `PASSWORD` option will not be changed before it is used for accessing the server's shared network file system.

However, it may be required to change the password to all-uppercase characters before it can be used. If this is necessary, you should either provide the password in this form or use the `CHANGEPASSWORDCASE=YES` option, which will cause it to be translated to all upper case characters.

Please note that the `CHANGEPASSWORDCASE` option will cause the `CHANGECASE` option to be ignored. If you omit the `CHANGEPASSWORDCASE` option, then the `CHANGECASE` option setting will be used instead.

#### 5.1.6. `CHANGECASE/S`

By default the password you provide with the `PASSWORD` option will not be changed before it is used for accessing the server's shared network file system.

However, it may be required to change the password to all-uppercase characters before it can be used. If this is necessary, you should either provide the password in this form or resort to the `CHANGECASE` option, which will cause it to be translated to all upper case characters.

#### 5.1.7. `DOMAIN=WORKGROUP/K`

This option may be omitted, in which case the **smbfs** program will ask the file server about the work group which it is a member of. Should the server fail to respond with this information, the **smbfs** program will use `WORKGROUP` as the domain name.

You should not need to specify the name of the work group or domain which the file server to connect to is a member of. However, if you do need to use it, you must **make sure that the name is not longer than 16 characters**. The name you provide will be translated to all upper case characters.

You need not provide for a work group or domain name on the command line. Alternatively, you may configure an environment variable whose contents will be used instead. The variable could be set up like this:

<pre>
SetEnv smbfs_workgroup *name of domain or work group*
Copy ENV:smbfs_workgroup ENVARC:
</pre>

You may also use the `smbfs_domain` environment variable in place of the `smbfs_workgroup` variable. The two are aliases for one another, but **smbfs** will read only one of the two.

#### 5.1.8. `NETBIOS/S`

Older server software such as *Microsoft Windows XP* may not respond to the requests of the **smbfs** program to connect to the shared network file system.

If the connection attempt fails immediately you may want to try the `NETBIOS` switch which tells the **smbfs** program to use an older protocol when trying to talk to the server.

#### 5.1.9. `CLIENT=CLIENTNAME/K`

The **smbfs** program will attempt to connect to the file server by providing the name of the computer you connect from.

In some cases this may be undesirable as the computer's name differs from what the file server expects.

You can use the `CLIENT` parameter to tell **smbfs** under which name it should announce itself to the server.

This parameter is optional and will be translated to all upper case characters; **it cannot be longer than 16 characters**.

Please note that the `CLIENT` parameter will be ignored unless the `NETBIOS` switch is used, too.

#### 5.1.10. `SERVER=SERVERNAME/K`

**smbfs** will attempt to connect to the file server by providing the name you specified using the `SHARE` option.

In some cases this may be undesirable as the server's name differs from what you specified as the share name. You can use the `SERVER` parameter to tell **smbfs** under which name it should contact the server.

This parameter is optional and will be translated to all upper case characters; **it cannot be longer than 16 characters**.

Please note that the `SERVER` parameter will be ignored unless the `NETBIOS` switch is used, too.

### 5.2. File name conversion

The shared network file system may not be using the same character set as your Amiga, so a translation may be required to allow you to access files and drawers.

The built-in default translation method should cover the original Amiga character set (*ISO-8859-1*, also known as *ISO-Latin-1*), but you have a choice to use a different method.

Please note that you can only pick one translation method, unless you disable translation altogether.

Also note that file and drawer names which cannot be represented on the Amiga due to lack of a suitable translation will be treated like "hidden" files and drawers. Names which are not safe to use on the Amiga, on account of containing reserved characters, will be "hidden" as well.

#### 5.2.1. `UNICODE/K`

The built-in default translation method is restricted to the part of Unicode which is covered by the *ISO-8859-1* character set. It is enabled by default, as if `UNICODE=on` had been used. You can disable it with `UNICODE=off`, which completely disables the translation.

**Note**: Some *Samba* versions will return corrupted file and drawer names unless Unicode support is enabled. Names which use only US-ASCII characters appear to be generally safe to use and are unlikely to suffer from corruption.

#### 5.2.2. `CP437/S`

The switch `CP437` enables a code page-based translation which works well enough with old *Samba* versions. "CP437" stands for *code page 437*, which is what the original IBM-PC would use.

The `CP437` switch disables Unicode support.

#### 5.2.3. `CP850/S`

The switch `CP850` enables a code page-based translation which works well enough with old *Samba* versions. "CP850" stands for *code page 850*, which is a variant of what the original IBM-PC would use. This variant is intended to be used in western Europe and is more compatible with the *ISO-8859-1* character set than the "CP437" variant.

The `CP850` switch disables Unicode support.

#### 5.2.4. `TRANSLATE=TRANSLATIONFILE/K`

How the individual names are to be translated is determined by the contents of a file name translation table file such as the ones that ship with *Workbench* in the `L:FileSystem_Trans` drawer.

The first 256 bytes of each such file must consist of the mapping of Amiga characters (this would be the *ISO-8859-1* character set) to the different character set, and the second 256 characters must describe a mapping back from the different character set to the Amiga.

In most cases the `L:FileSystem_Trans/INTL.crossdos` translation table file should be sufficient.

To specify which file contains the translation tables to use you would use the `TRANSLATIONFILE` parameter, e.g. `TRANSLATIONFILE=L:FileSystem_Trans/INTL.crossdos`. However, you might want to try the `CP850` switch instead which should produce the same effect.

The `TRANSLATE` option disables Unicode support.

### 5.3. Performance tuning

You may be able to put the **smbfs** program to good use, but overall performance, reliability and memory usage may still be somewhat lacking. These aspects may be tuned with the following parameters.

#### 5.3.1. `CACHE=CACHESIZE/N/K`

The file system attempts to optimize accesses to the file server when directory entries are being read.

This information is stored in a cache which by default will hold up to 170 entries. Since each entry will require about 255 bytes of storage, the entire 170 entry cache will occupy more than 40 KB of memory.

You may want to change this requirement, by making the cache smaller or larger using the `CACHESIZE` parameter. The size of the cache cannot be smaller than 10 entries.

#### 5.3.2. `CACHETABLES/N/K`

The cache can be used only by one directory at a time, which can cause problems if you are trying to delete a complete directory hierarchy, with several subdirectories (and their respective subdirectories). The cache will have to be refilled for each directory currently being processed. Consequently, **smbfs** will lose track of where it was when it read from the previous directory it was dealing with and must start over again.

You can mitigate these effects by increasing the number of caches which **smbfs** may use at a time. By default only a single cache, for a single directory, will be active (`CACHETABLES=1`). You can use more directory caches if you want to, but keep in mind that each cache will consume extra memory. If you want to use multiple caches, you might want to reduce the cache size.

#### 5.3.3. `RAISEPRIORITY/S`

The **smbfs** program can be run at a higher priority than it would normally do (normal would be priority 0), which might increase performance, but raise system load, too. If the `RAISEPRIORITY` switch is used, the **smbfs** program will run at the same priority as other Amiga file systems do (this would be priority 10).

#### 5.3.4. `TIMEOUT/N/K`

The **smbfs** program may lose the connection to the server during file system operations. While it will try to reestablish a connection to the server, some time has to pass before it becomes clear that the server connection is no longer working correctly.

You can set the number of seconds which have to pass before the **smbfs** program will stop waiting for the server to respond, shut down the connection and try again. For example, `TIMEOUT=5` will select a timeout of 5 seconds.

#### 5.3.5. `WRITEBEHIND/S`

The **smbfs** program can try to improve write performance by not waiting for the server to confirm that all the data just transmitted has in fact been stored. There is a risk involved in that the server may not have been able to store the data and you will never know about it.

Please note that the `WRITEBEHIND` switch has no effect if `PROTOCOL=nt1` is used because the **smbfs** program will then be using a different server write command which does not support the "write behind" functionality.

#### 5.3.6. `READTHRESHOLD/N/K` and `WRITETHRESHOLD/N/K`

The purpose of **smbfs** is chiefly to enable you to read and write files stored on a networked computer. To this end **smbfs** tries its best to squeeze as much performance out of the data transmission as possible.

Generally, each data transmission consists of two distinct parts. The first part contains information about the data that is being transmitted, such as its size and which file it belongs to. The second part is the data being transmitted.

**smbfs** can either send/receive both parts in a single step, or it can send/receive each part separately. If the data is received/sent in a single step, **smbfs** must spend extra time picking the data apart after it has received it (splitting it up into the information section and the data section), or combine the information and data sections prior to sending them as a single block of data.

This picking apart/combining comes with a cost because memory contents will have to be copied around. This cost can result in lower performance, which is why **smbfs** defaults to breaking up the transmission into two steps. Avoiding unnecessary memory copying operations is key to improving network performance on the Amiga.

However, it is not a given that breaking up the transmission into two steps will always be faster than using a single step, which is where the `READTHRESHOLD` and `WRITETHRESHOLD` options come in.

Transmissions which move large amounts of data tend to benefit significantly from sending/receiving each part of the transmission separately. The same may not be true for small amounts of data being transmitted.

Through the `READTHRESHOLD` and `WRITETHRESHOLD` options you can control the minimum transmission size at which **smbfs** will always send/receive each part of the transmission separately. In order to make sending small amounts of data more efficient, `WRITETHRESHOLD=1500` may be a good choice.

### 5.4. Compatibility

Both the file server and the software running on your Amiga may suffer from compatibility issues. For example, Amiga programs may be unable to deal with file names longer than 30 characters and then crash as a result. For some of these issues workarounds may be available.

#### 5.4.1. `CASE=CASESENSITIVE/S`

Some file servers treat files and drawers as different if their names differ only in whether individual letters are using upper/lower case characters. For example, on the Amiga we can expect that names such as `Work:File1` and `Work:file1` would refer to the same file, but you cannot expect this assumption to hold true for shared network file systems.

For file servers which would see `File1` and `file1` as different names you should activate the `CASESENSITIVE` switch to treat those files as being different.

There is a catch though: the AmigaDOS file naming scheme does not follow this model and you may run into problems when you are trying to use it. For example, in case sensitive mode attempting to access a file called `FILENAME` as `filename` or `Filename` will fail; you can access it only under the original name `FILENAME`.

By default, the **smbfs** program does not treat file and drawer names differently which only differ with respect to the case of letters.

#### 5.4.2. `DISABLEEXALL/S`

There are two different methods for reading the names of files and drawers stored in an Amiga volume or drawer.

The original method ("Examine/ExNext") will read the individual entries one at a time, and no name may be longer than 107 characters.

The second method ("ExAll"), introduced with Kickstart 2.0, can deliver more entries and more quickly than the original method. Also, directory entry names may be longer than "just" 107 characters (the **smbfs** program supports file and drawer names of up to 255 characters).

The **smbfs** program supports both methods, but there is a catch: Some Amiga software struggles to handle the number of entries delivered by the "ExAll" method, and names longer than 30 characters are a problem. Such software may malfunction and even crash.

To avoid problems with such software, the **smbfs** program can be made to pretend that it does not support the "ExAll" method. Use the `DISABLEEXALL` switch to disable the "ExAll" method.

Please note that if the `DISABLEEXALL` switch is used, the **smbfs** program will make files and drawers appear to be "hidden" if their names are longer than 107 characters.

#### 5.4.3. `ERROROUTPUT/K`

The **smbfs** program will try to print error messages in the shell window in a manner which bypasses output redirection. This means that if you decide to discard all the output by sending it to `NIL:`, then smbfs will still be able to show you error messages.

Where this is not a useful feature, you can tell the smbfs program to print both normal output and error messages in the same manner: use the `ERROROUTPUT=stdout` option.

#### 5.4.4. `MAXNAMELEN/N/K`

Some Amiga programs struggle with file and drawer names longer than 30 characters. They may malfunction and even crash when the **smbfs** program delivers them.

You can tell the **smbfs** program not to deliver any file or drawer names which are longer than a certain number of characters using the `MAXNAMELEN` option. For example, `MAXNAMELEN=30` would make files and drawers appear to be "hidden" if their names are longer than 30 characters.

#### 5.4.5. `MAXTRANSMIT/N/K`

You can fine-tune the size of the transmission buffer which the **smbfs** program uses when reading and writing files. The server may not have picked a buffer size which suits **smbfs** well. You can choose a smaller buffer size, if needed.

The minimum transmission buffer size is 8000 bytes (this is also the default buffer size), and the maximum permitted size is 65535 bytes.

Please note that the transmission buffer size you asked for need not be accepted by the file server, which may choose to use a much smaller buffer.

#### 5.4.6. `PROTOCOL/K`

The **smbfs** program talks to the file server using a protocol called **SMBv1**, using commands and data structures described by the **Common Internet File System** documentation.

There are several versions of the **SMBv1** protocol in use, and depending upon how old the server software is, **smbfs** may not work well with the file server.

It may help if you change the protocol level which the **smbfs** program uses. The default is `PROTOCOL=core` which should work well enough with *SMB* server software available before 2009, and which is particularly suited for use with the *Samba* server software. How do you know if the *Samba* server software is being used? Unless you are connecting to a *Microsoft Windows* server, you can practically assume that *Samba* will provide the shared network file system.

The alternative is `PROTOCOL=nt1` which might provide better compatibility and performance with *Microsoft Windows* systems.

When in doubt, stick with `PROTOCOL=core`.

#### 5.4.7. `SESSIONSETUP/K`

If the `UNICODE=ON` option is in effect, the **smbfs** program may not be able to connect to the server because it expects Unicode text to be used only after the server session has been established.

With `UNICODE=ON` the `SESSIONSETUP=DELAY` option will delay enabling Unicode support until after the session has been established. `SESSIONSETUP=NODELAY` will enable Unicode support at the earliest possible time instead.

The default is `SESSIONSETUP=DELAY` which works both with *Samba*, and seems to be required for *Microsoft Windows* systems.

### 5.5. Time conversion

The file server which the **smbfs** program connects to may not share the exact system time with your Amiga. Typically, it will expect file and drawer modification time information to be recorded in Universally Coordinated Time (UTC), rather than your local time zone (and the effects of daylight savings time).

You can, and should tell the **smbfs** program how far the local Amiga time deviates from UTC. By default the **smbfs** program will try to use the time zone information configured in the "Locale" preferences. This may not be sufficient, or even the wrong choice.

#### 5.5.1. `TZ=TIMEZONEOFFSET/N/K`

By default the file system will use the current Locale settings to translate between the local time and the time used by the file server.

For some configurations, however, this is impractical since the server's time zone is not configured properly. For these rare cases you may want to hard code a certain time zone offset using the `TIMEZONEOFFSET` option.

You need to provide the number of minutes to subtract from the local time in order to translate it into the corresponding UTC value. For example, in central Europe using CET, you would use `TZ=60` since CET is one hour ahead of UTC.

If you use the `TIMEZONEOFFSET` option, then the **smbfs** program will ignore the time zone information configured in the "Locale" preferences.

#### 5.5.2. `DST=DSTOFFSET/N/K`

This option can be used to adjust the file date stamps to take local daylight savings time into account.

The number to specify here is by how many minutes local time has been moved ahead, which is typically 60.

Note that **smbfs** does not know when daylight savings time begins and ends. It is up to you to select the correct adjustment value when appropriate.

### 5.6. Miscellaneous

#### 5.6.1. `DEVICE=DEVICENAME/K`, `ADDVOLUME/K` and  `VOLUME=VOLUMENAME/K`

By default the **smbfs** program will pick a unique file system device name such as `smbfs0:` and a volume name which is identical to the share name. For example, for `//192.168.0.1/pictures` the volume name would be `pictures` and a disk icon named **pictures** will appear in the Workbench window.

You may override the device name which **smbfs** will use, e.g. the `DEVICE=nas:` option will try to use `nas:` if possible. Please note that a device name has to be unique and **smbfs** may refuse to use it if there is already a file system device of that name.

You can tell **smbfs** not to add a volume, which may be useful because the native Amiga Samba port can hang as soon as the file system is started. In such cases, use the `ADDVOLUME=NO` option. Please note that the `ADDVOLUME=NO` option will keep **smbfs** from showing the file system's disk icon in the Workbench window. If you omit the `ADDVOLUME` option, **smbfs** will pretend that `ADDVOLUME=YES` was in effect.

If you want to use a specific volume name, use the `VOLUME` option,
e.g. `VOLUME=Sourcery:`. Otherwise a volume name derived from the share name will be used instead.

#### 5.6.2. `READONLY/S`

If you want to make sure that the contents of the file system mounted cannot
be modified or deleted by mistake, use the `READONLY` switch. This switch has
the same effect as using the `Lock` shell command. However, this protection
against modification will be enabled as soon as the file system has been
mounted and the protection cannot be removed with the `Lock` shell command.

#### 5.6.3. `OMITHIDDEN/S`

When requesting a directory listing, the file server may return some files and drawers tagged as being hidden. By default **smbfs** will not treat these "hidden" entries any different from the other directory entries, i.e. they are not hidden from view.

You can request that the hidden entries should be omitted from directory listings by using the `OMITHIDDEN` switch.

Note that even though a file or drawer may be hidden, you should still be able to open and examine it.

#### 5.6.4. `QUIET/S`

When started from shell, the **smbfs** program will print a message as soon as the
connection to the file server has been established.

If you do not want to see that message displayed, use the `QUIET` parameter. Please note that the **smbfs** program may still show error messages.

#### 5.6.5. `SETENV/S`

You may want to stop or disable/re-enabled a currently running **smbfs** program through the shell `Break` command, but it may be impractical to figure out which CLI process number is involved.

This is where the `SETENV` switch can help. If enabled, a global environment variable will be set which can be used by script files to figure out which CLI process number the respective **smbfs** program uses. The environment variable will be deleted as soon as the **smbfs** program exits.

The environment variable name will be `smbfs-process/<device name>`, e.g. `smbfs-process/smbfs0`, and it will contain the CLI process number which the `Break` command can make use of.

You can find out which **smbfs** programs are currently running like so:

<pre>
1> List ENV:smbfs-process
Directory "env:smbfs-process" on Wednesday 19-Sep-18
smbfs1                            3 ----rwed Today      10:43:16
smbfs0                            2 ----rwed Today      10:43:13

1> Echo "${smbfs-process/smbfs0}"
8
</pre>

Stopping a program can then be accomplished as follows:

<pre>
1> Break 8
</pre>

**Note**: The `SETENV` switch only has an effect if you start the **smbfs** program from the shell.

### 5.7. Debugging, diagnostics and bug reports

The **smbfs** program may not work as expected, and in order to help figuring out what went wrong, a special debug-enabled version of the program should be supplied along with the "normal" version you are using.

This special debug-enabled **smbfs** program ("smbfs.debug") can produce diagnostic and progress report information which may be stored in a log file.

#### 5.7.1. `DEBUGFILE/K`

If you want to capture the debug output of the **smbfs** program and have it stored in a file for reference, please state the name of the file here, e.g. `DEBUGFILE=ram:smbfs.log`.

If the file already exists, debug output will be appended to it.

#### 5.7.2. `DEBUGLEVEL=DEBUG/N/K`

By default the **smbfs** program operates in silent mode. It does not report what it is doing, it just tries to respond to file system requests. To obtain debugging output you may want to use the `DEBUG` option and specify a debug level greater than 0, e.g. `DEBUG=2`. The larger the number you specify the more debugging output will be created.

Note that unless you state which file the debug output should be written to, all debugging output will be sent to the shell window.

If you launched the **smbfs** program from *Workbench*, debug output will be produced using the operating system's debug output functionality which requires that you have a capturing program like *Sashimi* running in the background.


## 6. Known problems

The design of **smbfs** follows the original file system concept behind the code which the *Sharity-Light* file system is based upon. And that is a Unix file system which differs from Amiga specific file systems in many ways which can lead to problems which are discussed briefly below:

- Single threaded design

This means that it is not possible for several programs to fairly share the use of the file system. For example, a program that posts a long read request can tie up the file system almost exclusively for itself, and while it is busy all other clients will have to wait. Same goes for directory scanning.

- Poor scalability

This is associated with the single threaded design. When several programs are accessing the file system at the same time, overhead and unfair sharing of resources will drastically reduce the performance of the file system.

- Separation of file data and metadata

This means that the core of the file system treats the contents of a directory and the data attached to each file inside that directory as something different. This is a common concept with Unix file systems, but it is very different with Amiga file systems. In **smbfs** this data separation can cause problems when deleting files from a directory while that directory is being scanned, such as how this is being done by the `Delete` shell command. The effects of these problems are that a directory may not be deleted even though it is empty or that for the same directory the same file may be reported twice in the listing.

While there are no easy solutions for any of these problems, it does not mean that **smbfs** is unusable. You just have to be more careful when you use the file system. For example, if a directory's contents cannot be deleted due to one of the problems mentioned above, you might want to retry later.

It should be noted that the problems described above are not inherent to the original file system design. It's just that transferring that design to an Amiga file system created the problems.


## 7. Notes on smbfs version 2.1

**smbfs** is ultimatively based upon code created by reverse-engineering the **SMB** protocol. This effort led to the **smbfs** kernel module which was included with **Linux** 2.0.1 in 1995.

Subsequent work went into modifying the code, allowing it to be used as a file system on **NeXTSTEP** and various Unix versions (e.g. **NetBSD**, **Solaris** and **IRIX**) in the form of the 1996/1997 **Sharity** and **Sharity-Light** file systems. The Amiga **smbfs** is a port of **Sharity-Light**.

Because **smbfs** is based upon reverse-engineered code, it was always difficult to maintain it, even for minor changes needed to fix small bugs or to improve overall compatibility. How **smbfs** went about when communicating with a remote file server, and why, would remain unclear because the documentation which could shed some light on these matters was unavailable until around 2009/2012.

When I picked up development of **smbfs** again in 2016 I decided that I needed to know more about how the file system is supposed to work if I were ever going to be able to make robust changes to the code.

This is what led me to collecting more than 30 MB of documentation on **SMBv1**/**CIFS**, **NetBIOS** and the way in which Microsoft operating systems implemented these over the years.

What insights I managed to gain from this collection allowed me to update and rewrite the **smbfs** code so that its functionality and data structures now reflect the official **SMBv1**/**CIFS** documentation. The idea is that with these changes in place, future maintenance and enhancements should be easier to perform and to add. I wish I would not have needed to write my own **SMB** protocol disassembler and stumble through so many blind alleys, but this is how it goes with **SMBv1**/**CIFS**...

Now you know why it took almost two years to get from **smbfs** version 1.80 to version 2.1.


## 8. Credits

The **smbfs** file system is based upon prior work by Pål-Kristian Engstad, Volker Lendecke, Mark A. Shand, Donald J. Becker, Rick Sladkey, Fred N. van Kempen, Eric Kasten and Rudolf König. It is a direct descendant of the *Sharity-Light* file system written by Christian Starkjohann.

Versions including 1.80 and beyond incorporate changes from the *MorphOS* smbfs version 50.3, which was kindly provided by Frank Mariak. The individual changes came from Harry Sintonen, David Gerber and Frank Mariak.

The password encryption code was lifted from the *Samba* package. It was written by Andrew Tridgell and the Samba Team.

The great majority of changes and bug fixes which found their way into version 2.1 are due to Hubert Maier who patiently tested the various attempts to address the problems he reported.

Renaud Schweingruber kicked off the last stretch of the version 2.1 development work during 2018, encouraging me to complete the work I had begun.

Much of the testing and feedback during the development of version 2.1 in Summer 2018 was performed by and came from the www.a1k.org forum members, who put each test version through its paces, on hardware which I would have never been able to test it with. The rapid testing and feedback finally allowed version 2.1 to be released in 2018.

Robert Kidd provided detailed information on how to make the **smbfs** client/server authentication work with **OpenSolaris**/**OpenIndiana**. The changes made allow **smbfs** not just to work better with **OpenSolaris**, but with other **SMBv1**/**CIFS** server software, too.

## 9. Author

The *Sharity-Light* source code was adapted, wrapped into an AmigaOS layer, subsequently debugged and enhanced by Olaf Barthel. If you wish to contact me, you can reach me at:

    Olaf Barthel
    Gneisenaustr. 43
    D-31275 Lehrte

Or via e-mail:

    obarthel [at] gmx.net

If you want to submit a bug report or an enhancement request, please enclose sufficient information to allow me to make sense of the problem. That includes debugging logs produced using the `DEBUG` and `DEBUGFILE` options.

## 10. Source code

**smbfs** is distributed under the terms of the GNU General Public License (version 2). The source code should have accompanied this program; if it hasn't, please contact the author for a copy.

The program was compiled using the *SAS/C* 6.58 compiler, with the *Roadshow* SDK providing for the TCP/IP stack API header files.
