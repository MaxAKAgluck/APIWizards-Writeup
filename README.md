
# TryHackMe - APIWizards Breach Writeup

This is a short writeup about the [https://tryhackme.com/room/apiwizardsbreach](https://tryhackme.com/room/apiwizardsbreach) room which is about Linux DFIR, difficulty is Medium.

## Questions and Answers

### Which programming language is a web application written in?

Answer is Python, of course, and because the answer is 6 letters long I typed it in while waiting for the Box to load and reading through introduction.
(A proper way is to cd into apiservice and look at files there - main.py.)

<img width="940" height="326" alt="image" src="https://github.com/user-attachments/assets/f51ab084-a16c-40e9-a48f-fc4359c4fe56" />

### What is the IP address that attacked the web server?

Immediate thought is to check out the nginx logs since intro text mentioned serving apps through it -> go to /var/log/nginx and look into access.log.1 we see lots of entries from 149.34.244.142 which seems to perform directory brute forcing on server.

<img width="940" height="170" alt="image" src="https://github.com/user-attachments/assets/d9ba84fc-86da-48fb-88c5-1ba7a3443bd0" />

### Which vulnerability was found and exploited in the API service?

Here I thought that logs again would be useful and scrolling access.log.1 for a bit saw tons of 404 requests so I filtered for 200 ones and saw this:

<img width="940" height="76" alt="image" src="https://github.com/user-attachments/assets/1c0e2732-7366-405f-acf3-9e882e3a6cae" />

Long URL encoded strings are a bad sign for sure :O, so I decoded it:

```
GET /api/time?tz="; mkdir /home/dev/.ssh && chmod 700 /home/dev/.ssh # HTTP/1.1
```

This seems like the answer – command injection, but the answer is 3 words so it is OS command injection.

### Which file contained the credentials used to privesc to root?

I decided to first check out the code more since the attacker landed in dev shell and he probably went there too. In src folder we see a config file:

<img width="940" height="246" alt="image" src="https://github.com/user-attachments/assets/e8aa21c9-7359-445d-b751-3bca1c2244fe" />

Which has plaintext password which attacker just used and got a root shell :o.

### What file did the hacker drop and execute to persist on the server?

Decided to check the root history and since the attacker didn't clean it afterwards, we see lots of useful info:

<img width="940" height="271" alt="image" src="https://github.com/user-attachments/assets/5a5fd9b9-ff98-4f5d-bf1d-9c93e2468d27" />

We see the malware is called rooter2

### Which service was used to host the "rooter2" malware?

Again, root history shows it was transfer[.]sh

### Which two system files were infected to achieve cron persistence?

Decided to run usual commands to check crontabs - cat /etc/crontab and a script to enumerate user's crontabs:

```
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== Crontab for $user ==="
    crontab -u $user -l 2>/dev/null
done
```

After checking main crontab I found an entry:

<img width="940" height="229" alt="image" src="https://github.com/user-attachments/assets/e0f31859-1373-407b-bf58-ac88b4b11ac4" />

This looks suspicious enough, next check environment variables on system to see what this means:

<img width="940" height="77" alt="image" src="https://github.com/user-attachments/assets/a7b5e3f0-5701-4f2d-82bf-facdc1dbc66b" />

And we find a command for a bind shell.
Answers are /etc/crontab and /etc/environment

### What is the C2 server IP address of the malicious actor?

We already saw this, answer is 5.230.66.147, this can also be found in root bash history.

### What port is the backdoored bind bash shell listening at?

This requires checking network connections, using standard ss -tulnp:

<img width="940" height="86" alt="image" src="https://github.com/user-attachments/assets/41202c4a-cf49-45a8-be6f-9a754b4eadde" />

We see a nc process and port 3578 which is our answer.

### How does the bind shell persist across reboots?

This suggests attacker created a service that starts up even after reboot (also next question hints that it is a systemd service), I checked directories for suspicious entries:

```
ls -la /etc/systemd/system/
ls -la /lib/systemd/system/
```

And after a while I checked the socket.service (also there is a useful command for checking services that are not part of the OS:

```
comm -23 \
  <(ls /etc/systemd/system | sort) \
  <(ls /usr/lib/systemd/system | sort)
```

<img width="588" height="342" alt="image" src="https://github.com/user-attachments/assets/8588e450-141b-4b4b-85ec-24fae949fda0" />

So the socket.service is the answer.

### Which port is blocked on the victim's firewall?

First I checked ufw: sudo ufw status, but it wasn't turned on, so I went to iptables:

<img width="940" height="200" alt="image" src="https://github.com/user-attachments/assets/d48489ff-40f3-4ad6-addc-2e6aa673253b" />

And the answer is 3578.

### How do the firewall rules persist across reboots?

I didn't know much on the topic so I researched and asked ChatGPT and checked the configs:

```
ls /etc/iptables/
ls /etc/nftables.conf
ls /etc/rc.local
```

I found nothing, and the systemctl didn't show anything too.
After more research and questions I decided to check .bashrc file which runs after you open a terminal and can be used for persistence:

<img width="940" height="206" alt="image" src="https://github.com/user-attachments/assets/8e58d7c8-81ed-4a04-b397-904ce553479f" />

At the end of file root runs the iptables rules, so this .bashrc is the answer.

### How is the backdoored local Linux user named?

Running grep on /etc/passwd:

<img width="940" height="180" alt="image" src="https://github.com/user-attachments/assets/45a40202-8e5e-4659-8ef7-841267b731c6" />

Revealed users with login shells and the one with /bin/bash (and sudo access) is our answer – support.

### Which privileged group was assigned to the user?

Use 'id support' (used in previous question also) we see that he has sudo.

### What is the strange word on one of the backdoored SSH keys?

<img width="940" height="42" alt="image" src="https://github.com/user-attachments/assets/13af318b-57aa-432b-b282-85628a64cc45" />

The answer is ntsvc.

### Can you spot and name one more popular persistence method? Not a MITRE technique name.

I had to use the hint on this one and it hinted at suid binaries.

### What are the original and the backdoored binaries from question 6?

Using find / -perm -4000 -type f 2>/dev/null:

<img width="501" height="550" alt="image" src="https://github.com/user-attachments/assets/79e4d6ea-6d07-46da-961e-74ed9a880cd3" />

I checked sudo and su and pkexec as most promising and found they are unchanged, I didn't know what is clamav and found out its an AV, but the problem is that it isn't installed:

```
root@ip-10-10-177-144:/var/log/nginx# dpkg --verify clamav
dpkg: package 'clamav' is not installed
```

Next we check info on that binary:

<img width="940" height="185" alt="image" src="https://github.com/user-attachments/assets/1d9afd45-25bb-4fa4-96b4-d989bfcd6cdc" />

This is a bash shell and md5 hash is of /bin/bash so this is a copy of bash.

### What technique was used to hide the backdoor creation date?

The technique according to Google is Timestomping:

<img width="940" height="50" alt="image" src="https://github.com/user-attachments/assets/e2c441cf-0d8e-43a8-8f48-8531f90787ed" />

Binary seems like it was modified long ago, we can use stat /usr/bin/clamav to verify it is wrong:

<img width="940" height="226" alt="image" src="https://github.com/user-attachments/assets/77541f9b-20c8-4187-878d-aea807e30552" />

So indeed it was changed on 30 July 2023 which is consistent with the timeline of the attack.

### What file was dropped which contained gathered victim information?

This could have been answered by us long ago since the answer is in root bash history:

<img width="940" height="96" alt="image" src="https://github.com/user-attachments/assets/89dde354-629f-41c6-8a98-1696b7009e62" />

Answer is .dump.json

### According to the dropped dump, what is the server's kernel version?

I went to file location and found it:

<img width="940" height="33" alt="image" src="https://github.com/user-attachments/assets/9866ac60-c5ce-4327-a3b3-3136272fea42" />

It contains a bunch of B64 strings one of which after decoding reveals:

<img width="940" height="125" alt="image" src="https://github.com/user-attachments/assets/8a6fd8da-6d66-43c5-82dc-03bf818040a9" />

Answer is 5.15.0-78-generic.

### Which active internal IPs were found by the "rooter2" network scan?

Again, the answer is in dump file:

<img width="850" height="187" alt="image" src="https://github.com/user-attachments/assets/40e48d94-ceb1-4d49-8d3f-26e603245de8" />

Attacker noted 192.168.0.21 and ports 22,80 and 192.168.0.22 and ssh port
(Also, root history shows that he ran a nc port scan on .22 address)

### How did the hacker find an exposed HTTP index on another internal IP?

Yes, root history again and the answer is the port scan command:

```
nc -zv 192.168.0.22 1024-10000 2>&1 | grep -v failed
```

### What command was used to exfiltrate the CDE database from the internal IP?

Just check root history again:

```
wget 192.168.0.22:8080/cde-backup.csv
```

### What is the most secret and precious string stored in the exfiltrated database?

We see in history the attacker renamed the file to review.csv:

<img width="940" height="272" alt="image" src="https://github.com/user-attachments/assets/5d7ffdcb-ec60-4d2c-b5c4-b1973d0ee47c" />

Since he downloaded this while in /root I went there to look and the file is there:

<img width="940" height="302" alt="image" src="https://github.com/user-attachments/assets/e5902654-8644-41f6-9972-3504c001ce42" />

And the final flag is just the first entry.

## Final Thoughts

Overall, a very interesting and engaging room, ideal for practicing Linux forensics and shell commands. It has questions on the whole attack chain – from initial access to data exfiltration (with the focus on persistence mechanisms). The only difficulty is that the hints are distributed in a very strange way – there is a hint that the strings in dropped dump are encoded (which is very obvious and considering in the previous question we know the file location this is just a matter of decrypting b64) but at the same time the question about persistence technique just hints that it is a common MITRE technique, which I would say is not that helpful.


