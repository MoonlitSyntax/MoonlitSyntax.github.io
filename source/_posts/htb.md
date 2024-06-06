---
title: htb
date: 2023-09-10 18:10:41
categories:
- 网络安全
tags:
- web
- 渗透测试
description: |
    靶场
---

## Linux

### find

| **选项**              | **描述**                                                     |
| --------------------- | ------------------------------------------------------------ |
| `-type f`             | 由此，我们定义了搜索对象的类型。在这种情况下，“ `f`”代表“ `file`”。 |
| `-name *.conf`        | 使用“ `-name`”，我们指示我们正在查找的文件的名称。星号 ( `*`) 代表带有“ ”`.conf`扩展名的“所有”文件。 |
| `-user root`          | 该选项过滤所有者为 root 用户的所有文件。                     |
| `-size +20k`          | 然后，我们可以过滤所有找到的文件，并指定我们只想查看大于 20 KiB 的文件。 |
| `-newermt 2020-03-03` | 通过此选项，我们可以设置日期。仅显示比指定日期更新的文件。   |
| `-exec ls -al {} \;`  | 此选项执行指定的命令，使用大括号作为每个结果的占位符。反斜杠会转义下一个字符，以免 shell 解释该字符，因为否则分号将终止命令并且无法到达重定向。 |
| `2>/dev/null`         | 这是`STDERR`到“ `null device`”的重定向，我们将在下一节中讨论它。此重定向可确保终端中不会显示任何错误。此重定向必须`not`是“find”命令的一个选项。 |

------

2020年3月3日之后创建的小于28k但大于25k的配置文件

`find / -type f -name *.conf -newermt 2020-03-03 -size +25k -size -28k 2>/dev/null`

### locate

`locate *.bak`

很快

### 文件描述符

1. 输入数据流
   - `STDIN – 0`
2. 输出数据流
   - `STDOUT – 1`
3. 与发生的错误相关的输出数据流。
   - `STDERR – 2`

`find / -iname "*.log" 2>/dev/null | wc -l`不区分大小写 重定向错误数据

### 一些计数问题

列出已安装的软件包：

```bash
dpkg --list | wc --lines
```

查看软件包是否已安装：

```bash
dpkg --list | grep package
```

```bash
dpkg -l | grep -c '^ii'#这个不错
```

有一些微妙的变体，例如`dpkg -l | grep -c '^?i'`您想要包含已安装但已请求删除的软件包。另一种方法是

```bash
aptitude search '~i' |wc -l
```

您甚至可以直接查看 dpkg 数据库：

```bash
sh -c 'set /var/lib/dpkg/info/*; echo $#'
```

这包括未安装但仍保留配置文件的软件包；您可以使用 列出这些`dpkg -l | grep '^rc'`。

### 读文件

#### more

`Q` to leave

#### less

#### head

如果没有另外指定，则打印给定文件或输入的前十行。

#### tail

返回最后十行。

#### sort

结果排序

#### grep配合管道符

like `cat /etc/passwd | grep "/bin/bash"`

or `cat /etc/passwd | grep -v "false\|nologin"`排除特定结果

#### cut

`cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1`

不会

#### tr

`cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "`

不会

#### sed column wc awk

.......不会

### 练习

#### 找出有多少服务正在监听我的接口（仅限 ipv4，而不是 localhost）

```bash
ss -l -4 | grep -v "127\.0\.0" | grep "LISTEN" | wc -l
```

- **-l** : 只显示监听服务
- **-4**：仅显示ipv4
- **-grep -v "127.0.0"**：排除所有本地主机结果
- **-grep "LISTEN"**：更好地仅过滤监听服务
- **wc -l** : 计数结果

#### 查看ProFTPd的用户

 `ps aux | grep -i proftpd`

#### 啥啊这是

`curl https://www.inlanefreight.com | grep -Po "https://www.inlanefreight.com/[^'\"] *" | sort -u | wc -l`

不懂绷不住

### regex

| **Operators** | **Description** |                                                              |
| ------------- | --------------- | ------------------------------------------------------------ |
| 1             | `(a)`           | The round brackets are used to group parts of a regex. Within the brackets, you can define further patterns which should be processed together. |
| 2             | `[a-z]`         | The square brackets are used to define character classes. Inside the brackets, you can specify a list of characters to search for. |
| 3             | `{1,10}`        | The curly brackets are used to define quantifiers. Inside the brackets, you can specify a number or a range that indicates how often a previous pattern should be repeated. |
| 4             | `|`             | Also called the OR operator and shows results when one of the two expressions matches |
| 5             | `.*`            | Also called the AND operator and displayed results only if both expressions match |

`grep -E "(my|flase)" /etc/passwd`

### 权限管理

#### 文件属性

- 第一个字符表示文件类型。常见的类型有：
  - `-`：普通文件
  - `d`：目录
  - `l`：符号链接
- 接下来的九个字符表示文件的权限，分为三组：
  - 第1-3位：文件所有者的权限
  - 第4-6位：属于文件的组的权限
  - 第7-9位：其他用户的权限
- 每组中的权限可以是以下字符：
  - `r`：读权限
  - `w`：写权限
  - `x`：执行权限
  - `-`：没有相应的权限

#### 变更所有者

要更改文件或目录的所有者和/或组分配，我们可以使用该`chown`命令。语法如下：

##### 语法 - chown

```shell-session
cry0l1t3@htb[/htb]$ chown <user>:<group> <file/directory>
```

在此示例中，“shell”可以替换为任意文件或文件夹。

```shell-session
cry0l1t3@htb[/htb]$ chown root:root shell && ls -l shell

-rwxr-xr--   1 root root 0 May  4 22:12 shell
```

### 用户管理

#### shadow

```shell-session
Dionysus13931@htb[/htb]$ cat /etc/shadow

cat: /etc/shadow: Permission denied
```

 以 root 身份执行

```shell-session
Dionysus13931@htb[/htb]$ sudo cat /etc/shadow

root:<SNIP>:18395:0:99999:7:::
daemon:*:17737:0:99999:7:::
bin:*:17737:0:99999:7:::
<SNIP>
```

| **命令**   | **描述**                                                     |
| ---------- | ------------------------------------------------------------ |
| `sudo`     | 以不同用户身份执行命令。                                     |
| `su`       | 该`su`实用程序通过 PAM 请求适当的用户凭据并切换到该用户 ID（默认用户是超级用户）。然后执行一个 shell。 |
| `useradd`  | 创建新用户或更新默认的新用户信息。                           |
| `userdel`  | 删除用户帐户和相关文件。                                     |
| `usermod`  | 修改用户帐户。                                               |
| `addgroup` | 将组添加到系统。                                             |
| `delgroup` | 从系统中删除一个组。                                         |
| `passwd`   | 更改用户密码。                                               |

#### 练习1

- 创建

  为新用户 `newuser` 创建一个账户并自动为其创建主目录，你可以使用以下命令：

  ```bash
  bashCopy code
  useradd -m newuser
  ```

  如果你想指定一个特定的主目录（而不是默认的，通常位于 `/home/username` 的目录），你可以使用 `-d` 或 `--home` 选项，并指定路径，如：

  ```bash
  bashCopy code
  useradd -m -d /path/to/custom/home newuser
  ```

  这将为 `newuser` 创建一个账户，并将其主目录设置为 `/path/to/custom/home`，同时创建这个目录（如果它不存在的话）

- 锁定

  要锁定名为 `username` 的用户账户，你可以使用以下命令：

  ```bash
  bashCopy code
  usermod --lock username
  ```

- su选择不同用户

  `su username --command "whoami"`

### 包管理

| **命令**   | **描述**                                                     |
| ---------- | ------------------------------------------------------------ |
| `dpkg`     | 这`dpkg`是一个安装、构建、删除和管理 Debian 软件包的工具。主要且更用户友好的前端`dpkg`是 aptitude。 |
| `apt`      | Apt 为包管理系统提供了高级命令行界面。                       |
| `aptitude` | Aptitude 是 apt 的替代品，是包管理器的高级接口。             |
| `snap`     | 安装、配置、刷新和删除快照包。Snap 可以安全地分发云、服务器、桌面和物联网的最新应用程序和实用程序。 |
| `gem`      | Gem 是 RubyGems 的前端，RubyGems 是 Ruby 的标准包管理器。    |
| `pip`      | Pip 是一个 Python 包安装程序，建议用于安装 Debian 存档中不可用的 Python 包。它可以与版本控制存储库（目前仅 Git、Mercurial 和 Bazaar 存储库）配合使用，广泛记录输出，并通过在开始安装之前下载所有要求来防止部分安装。 |
| `git`      | Git 是一个快速、可扩展、分布式版本控制系统，具有异常丰富的命令集，可提供高级操作和对内部的完全访问。 |

### 后台

有时需要将我们刚刚启动的扫描或进程放在后台，以继续使用当前会话与系统交互或启动其他进程。正如我们已经看到的，我们可以使用快捷方式来做到这一点`[Ctrl + Z]`。如上所述，我们`SIGTSTP`向内核发送信号，内核会挂起进程。

```shell-session
Dionysus13931@htb[/htb]$ ping -c 10 www.hackthebox.eu

Dionysus13931@htb[/htb]$ vim tmpfile
[Ctrl + Z]
[2]+  Stopped                 vim tmpfile
```

现在可以使用以下命令显示所有后台进程。

```shell-session
Dionysus13931@htb[/htb]$ jobs

[1]+  Stopped                 ping -c 10 www.hackthebox.eu
[2]+  Stopped                 vim tmpfile
```

该`[Ctrl] + Z`快捷方式会暂停进程，并且不会进一步执行它们。为了让它在后台运行，我们必须输入命令`bg`将进程置于后台。

```shell-session
Dionysus13931@htb[/htb]$ bg

Dionysus13931@htb[/htb]$ 
--- www.hackthebox.eu ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 113482ms

[ENTER]
[1]+  Exit 1                  ping -c 10 www.hackthebox.eu
```

`&`另一种选择是在命令末尾使用 AND 符号 ( ) 自动设置进程。

```shell-session
Dionysus13931@htb[/htb]$ ping -c 10 www.hackthebox.eu &

[1] 10825
PING www.hackthebox.eu (172.67.1.1) 56(84) bytes of data.
```

该过程完成后，我们将看到结果。

如果我们想让后台进程进入前台并再次与之交互，我们可以使用该`fg <ID>`命令。

```shell-session
Dionysus13931@htb[/htb]$ fg 1
ping -c 10 www.hackthebox.eu

--- www.hackthebox.eu ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9206ms
```

### 执行多个命令

- `;`

  忽略先前命令的错误和结果

- `&&`

  其中一条命令出错,后面的将不会执行

- `|`

  不仅取决于前面进程的正确无差错操作，还取决于前面进程的结果

#### 练习2

使用“systemctl”命令列出所有服务单元，并提交单元名称和描述“加载由 snapd 内部管理的 AppArmor 配置文件”作为答案。

`systemctl list-units --type=service | grep snapd | grep AppArmor`

`syslog.server`的类型

`systemctl show syslog.service -p Type`
