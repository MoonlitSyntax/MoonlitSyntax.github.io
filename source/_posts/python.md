---
title: python
date: 2023-04-21 13:29:12
categories:
- python
tags:
- web
description: |
    爬虫
---
### 变量赋值

#### 字符串

```bash
  astr="python"      //[起始：结束（不包含）：步长]
  print(astr[0:2])   //py 
  print(astr[-1])
  print(astr[::-1])
```

#### 列表

```bash
  alist=["tom","jerry"] //可以写入不同类型的数据
  alist[0]
  if name in alist :
      print("Yes");
```

#### 元组

```bash
  atuple=("tom","jerry") 
```

#### 字典

```bash
  userdict={"tom":"123","jerry":"456"}//字典没有索引值 键值对来取值
  if name in userdict and password==userdict[username]:
      print("Yes")
```

### 文件读取写入

>f=open("路径","#")    //#=rb···

- `close()` - 关闭文件，释放相关的系统资源
- `read(size=-1)` - 从文件中读取指定字节数的数据，如果未指定 size 或 size 为负数，则读取整个文件
- `readline(size=-1)` - 从文件中读取一行数据，可以指定最大读取字节数
- `readlines(hint=-1)` - 从文件中读取所有行，并返回一个包含所有行的列表，可以指定最大读取字节数
- `write(text)` - 将指定的文本写入文件
- `writelines(lines)` - 向文件中写入一个字符串列表，不添加行分隔符
- `seek(offset[, whence])` - 改变文件指针的位置，offset 表示相对于 whence 的偏移量，whence 可选值：0（文件开头，默认），1（当前位置），2（文件末尾）
- `tell()` - 返回文件指针的当前位置，相对于文件开头
- `flush()` - 将文件缓冲区的内容写入文件，并清空缓冲区
- `fileno()` - 返回文件的文件描述符（整数）
- `isatty()` - 检查文件是否为终端设备（例如控制台、终端窗口等）
- `truncate(size=None)` - 裁剪文件到指定大小，如果未指定 size，则裁剪到当前文件指针位置

### 模块和函数

```python
    """
    模块作用
    包含功能
    other
    """
    # 变量类型 作用
    def name():
        #函数作用 
        return 


    #主程序中：
    import name
```

### 异常捕获

```python
    try:
        action
    except errimfomation:
        explaination
    except ···：
        more 
```

### class

a example:

```python
class SKB(object):
    color = "green"
    hands = 2
    def __init__(self,COLOR,HANDS):
        #初始化
        self.color=COLOR
        self.hands=HANDS
    def dahulu(self):
        print("轰······")
        #  "number%d" %(number)
    def jiaobian(self):
        print("我没有")
    def myaihao(self):
        print("傻逼SKB")

mysheyou = SKB("green",2)
mysheyou.dahulu()
mysheyou.myaihao()
mysheyou.jiaobian()
```

### 爬虫

#### python获取代码

```python
import urllib.request  

class GetHtml(object):
    def __init__(self, URL,HEAD):  
        self.url = URL
        self.head=HEAD

    def get_index(self):
        self.request = urllib.request.Request(self.url)
        self.request.add_header("user-agent",self.head)
        self.response=urllib.request.urlopen(self.request)
        return self.response.read()

html = GetHtml("https://siren.blue","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
print(html.get_index()) 

```

#### 正则表达式

```python
#re模块
"""
.       单个字符匹配
[]      括号内的内容会被逐一匹配
\d      匹配单个数字
\w      [0-9a-zA-Z]
\s      空白字符 空格 tab
*       匹配左邻字符出现0次或多次
+       左邻字符出现一次或多次
?       左邻字符出现一次或0次
{n,m}   左邻字符出现n 到 m次
^       以什么字符串开头
$       以什么字符串结尾
()\\1   括号内保存 分组保存
"""
re.findall(".x","")
re.findall("[Gf]ood","")
re.findall("hello","")# 直接匹配
re.findall("Good｜food","")
re.findall("go*gle","i like google not ggle goooogle and gogle")
re.findall("go+gle","")
re.findall("style/\w{60}.jpg","")
```
