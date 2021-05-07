# 米斯特白帽培训讲义 工具篇 Nmap

> 讲师：[gh0stkey](https://www.zhihu.com/people/gh0stkey/answers)

> 整理：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0)

## 介绍

Nmap（网络映射器）是由 Gordon Lyon 涉及，用来探测计算机网络上的主机和服务的一种安全扫描器。为了绘制网络拓补图，Nmap 发送特制的数据包到目标主机，然后对返回数据包进行分析。Nmap 是一款枚举和测试网络的强大工具。

Nmap 有两种界面：可视化界面和命令行界面。

## 下载

https://nmap.org/download.html

## 使用

典型用途：

+   通过对设备或者防火墙的探测来审计其安全性。
+   探测目标主机的开放端口。
+   网络存储、网络映射、维护和资产管理。（这个有待深入）
+   通过识别新的服务器审计网络的安全性。
+   探测网络上的主机。

### 简单扫描

Nmap 默认使用 ICMP ping 和 TCP 全连接（`-PB`）进行主机发现，以及使用 TCP 全连接（`-sT`） 执行主机扫描。默认扫描端口是 1 ~ 1024，以及其列表中的常用端口。

语法：

```
nmap <目标 IP>
```

例子：

```
C:\Users\asus> nmap 192.168.1.1

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 10:37 ?D1ú±ê×?ê±??
Nmap scan report for localhost (192.168.1.1)
Host is up (0.0062s latency).
Not shown: 993 closed ports
PORT      STATE    SERVICE
21/tcp    filtered ftp
22/tcp    filtered ssh
23/tcp    filtered telnet
53/tcp    open     domain
80/tcp    open     http
49152/tcp open     unknown
49153/tcp open     unknown
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)

Nmap done: 1 IP address (1 host up) scanned in 3.40 seconds
```

多个 IP 可以以逗号分隔：`192.168.1.1,2,3,4,5`，也可以使用短横线来表示范围：`192.168.1.1-255`，也可以使用 CIDR 记法：`192.168.1.0/24`。

### 显示详细结果

```
nmap -vv <目标 IP>
```

```
C:\Users\asus> nmap -vv 192.168.1.1

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 10:47 ?D1ú±ê×?ê±??
Initiating ARP Ping Scan at 10:47
Scanning 192.168.1.1 [1 port]
Completed ARP Ping Scan at 10:47, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:47
Completed Parallel DNS resolution of 1 host. at 10:47, 0.01s elapsed
Initiating SYN Stealth Scan at 10:47
Scanning localhost (192.168.1.1) [1000 ports]
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 53/tcp on 192.168.1.1
Discovered open port 49153/tcp on 192.168.1.1
Discovered open port 49152/tcp on 192.168.1.1
Completed SYN Stealth Scan at 10:47, 2.27s elapsed (1000 total ports)
Nmap scan report for localhost (192.168.1.1)
Host is up, received arp-response (0.0052s latency).
Scanned at 2016-12-22 10:47:09 ?D1ú±ê×?ê±?? for 3s
Not shown: 993 closed ports
Reason: 993 resets
PORT      STATE    SERVICE REASON
21/tcp    filtered ftp     no-response
22/tcp    filtered ssh     no-response
23/tcp    filtered telnet  no-response
53/tcp    open     domain  syn-ack ttl 64
80/tcp    open     http    syn-ack ttl 64
49152/tcp open     unknown syn-ack ttl 64
49153/tcp open     unknown syn-ack ttl 64
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)

Read data files from: C:\Program Files (x86)\Nmap
Nmap done: 1 IP address (1 host up) scanned in 2.92 seconds
           Raw packets sent: 1004 (44.160KB) | Rcvd: 998 (39.924KB)
```

### 自定义端口

```
nmap <目标 IP> -p <端口>
```

```
C:\Users\asus> nmap 192.168.1.1 -p 1-500

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 10:59 ?D1ú±ê×?ê±??
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.1.1
Host is up (0.0061s latency).
Not shown: 495 closed ports
PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp filtered ssh
23/tcp filtered telnet
53/tcp open     domain
80/tcp open     http
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)

Nmap done: 1 IP address (1 host up) scanned in 2.08 seconds
```

端口可以是单个，也可以是多个，多个端口可以以逗号分隔，比如`21,22,23,53,80`，也可以使用短横线指定范围，比如`1-1024`。


### Ping 扫描

```
nmap -sP <目标 IP>
```

Ping 扫描其实就是只执行主机发现，不扫描具体端口。大家可以看到结果中没有端口的信息，只告诉你主机通不通，所以也很快。

```
C:\Users\asus> nmap 192.168.1.1 -sP

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 10:52 ?D1ú±ê×?ê±??
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.1.1
Host is up (0.0030s latency).
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)
Nmap done: 1 IP address (1 host up) scanned in 0.59 seconds
```

与之相反，有一个选项是只执行端口扫描，不执行主机发现的，是`-PN`（或`-P0`）。

```
C:\Users\asus> nmap 192.168.1.1 -PN

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 10:54 ?D1ú±ê×?ê±??
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.1.1
Host is up (0.0062s latency).
Not shown: 993 closed ports
PORT      STATE    SERVICE
21/tcp    filtered ftp
22/tcp    filtered ssh
23/tcp    filtered telnet
53/tcp    open     domain
80/tcp    open     http
49152/tcp open     unknown
49153/tcp open     unknown
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)

Nmap done: 1 IP address (1 host up) scanned in 2.47 seconds
```

### 操作系统类型检测


```
nmap -O <目标 IP>
```

```
C:\Users\asus> nmap www.baidu.com -O

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 11:03 ?D1ú±ê×?ê±??
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for www.baidu.com (61.135.169.125)
Host is up (0.0038s latency).
Other addresses for www.baidu.com (not scanned): 61.135.169.121
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: switch
Running (JUST GUESSING): HP embedded (86%)
OS CPE: cpe:/h:hp:procurve_switch_4000m
Aggressive OS guesses: HP 4000M ProCurve switch (J4121A) (86%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.35 seconds
```


### 组合扫描

比如我们要扫描1 ~ 1024 端口，详细输出，并且探测操作系统。

```
C:\Users\asus> nmap 192.168.1.1 -p 1-1024 -vv -O

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 11:06 ?D1ú±ê×?ê±??
Initiating ARP Ping Scan at 11:06
Scanning 192.168.1.1 [1 port]
Completed ARP Ping Scan at 11:06, 0.14s elapsed (1 total hosts)
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Initiating SYN Stealth Scan at 11:06
Scanning 192.168.1.1 [1024 ports]
Discovered open port 53/tcp on 192.168.1.1
Discovered open port 80/tcp on 192.168.1.1
Completed SYN Stealth Scan at 11:06, 2.03s elapsed (1024 total ports)
Initiating OS detection (try #1) against 192.168.1.1
Retrying OS detection (try #2) against 192.168.1.1
Retrying OS detection (try #3) against 192.168.1.1
Retrying OS detection (try #4) against 192.168.1.1
Retrying OS detection (try #5) against 192.168.1.1
Nmap scan report for 192.168.1.1
Host is up, received arp-response (0.0014s latency).
Scanned at 2016-12-22 11:06:44 ?D1ú±ê×?ê±?? for 15s
Not shown: 1019 closed ports
Reason: 1019 resets
PORT   STATE    SERVICE REASON
21/tcp filtered ftp     no-response
22/tcp filtered ssh     no-response
23/tcp filtered telnet  no-response
53/tcp open     domain  syn-ack ttl 64
80/tcp open     http    syn-ack ttl 64
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.01%E=4%D=12/22%OT=53%CT=1%CU=37502%PV=Y%DS=1%DC=D%G=Y%M=6889C1%
OS:TM=585B4353%P=i686-pc-windows-windows)SEQ(SP=106%GCD=1%ISR=104%TI=Z%CI=Z
OS:%II=I%TS=U)SEQ(CI=Z%II=I%TS=U)SEQ(CI=Z%II=I)OPS(O1=M5B4NNSNW2%O2=M5B4NNS
OS:NW2%O3=M5B4NW2%O4=M5B4NNSNW2%O5=M5B4NNSNW2%O6=M5B4NNS)WIN(W1=16D0%W2=16D
OS:0%W3=16D0%W4=16D0%W5=16D0%W6=16D0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M5B4NNSNW2%
OS:CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y
OS:%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: C:\Program Files (x86)\Nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.21 seconds
           Raw packets sent: 1152 (54.954KB) | Rcvd: 1110 (48.462KB)
```

可以看出来没探测到什么东西，因为是路由器，大家这种情况认为是 Linux 就好了。

### 脚本（补充）

Nmap 有个叫做 NSE 的脚本引擎，也自带了一些脚本，更多脚本可以去官网下载。

脚本的类型有：

```
auth: 负责处理鉴权证书（绕开鉴权）的脚本  
broadcast: 在局域网内探查更多服务开启状况，如dhcp/dns/sqlserver等服务  
brute: 提供暴力破解方式，针对常见的应用如http/snmp等  
default: 使用-sC或-A选项扫描时候默认的脚本，提供基本脚本扫描能力  
discovery: 对网络进行更多的信息，如SMB枚举、SNMP查询等  
dos: 用于进行拒绝服务攻击  
exploit: 利用已知的漏洞入侵系统  
external: 利用第三方的数据库或资源，例如进行whois解析  
fuzzer: 模糊测试的脚本，发送异常的包到目标机，探测出潜在漏洞 intrusive: 入侵性的脚本，此类脚本可能引发对方的IDS/IPS的记录或屏蔽  
malware: 探测目标机是否感染了病毒、开启了后门等信息  
safe: 此类与intrusive相反，属于安全性脚本  
version: 负责增强服务与版本扫描（Version Detection）功能的脚本  
vuln: 负责检查目标机是否有常见的漏洞（Vulnerability），如是否有MS08_067
```

向命令行添加`--script=<类型>`来使用脚本。

下面演示了使用`default`脚本来探测主机上的服务。

```
C:\Users\asus> nmap --script=default 192.168.1.1

Starting Nmap 7.01 ( https://nmap.org ) at 2016-12-22 11:10 ?D1ú±ê×?ê±??
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.1.1
Host is up (0.0051s latency).
Not shown: 993 closed ports
PORT      STATE    SERVICE
21/tcp    filtered ftp
22/tcp    filtered ssh
23/tcp    filtered telnet
53/tcp    open     domain
| dns-nsid:
|_  bind.version: dnsmasq-2.49
80/tcp    open     http
|_http-title: Site doesn't have a title (text/html).
49152/tcp open     unknown
49153/tcp open     unknown
MAC Address: 68:89:C1:74:84:43 (Huawei Technologies)

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds
```

## 参考

+   [Nmap 脚本使用总结](http://www.2cto.com/article/201406/307959.html)

+   [Nmap 参考指南](https://www.gitbook.com/book/wizardforcel/nmap-man-page/details)

+   [Kali Linux 网络扫描秘籍 第三章 端口扫描（一）](http://www.jianshu.com/p/093b7386e1e8)

+   [Kali Linux 网络扫描秘籍 第三章 端口扫描（二）](http://www.jianshu.com/p/c484258dbc34)

+   [Kali Linux 网络扫描秘籍 第三章 端口扫描（三）](http://www.jianshu.com/p/29d97054217c)
