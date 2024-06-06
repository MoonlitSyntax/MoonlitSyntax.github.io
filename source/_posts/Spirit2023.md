---
title: Spirit2023
date: 2023-08-30 11:07:43
categories:
- 网络安全
tags:
- web 
- 出题
description: |
    出题喵
---

### web??misc

unicode的简单利用

`dionysus13931/spirit002:latest`

`docker buildx build --platform linux/amd64 -t dionysus13931/spirit002:latest . --push`

### ez_xxe

`dionysus13931/spirit003:latest`

### python jwt

`dionysus13931/spirit004:latest`

`dionysus13931/spirit004:v1`

### python session

`dionysus13931/spirit007:latest`

### hiden

```php
<?php
error_reporting(0);
echo "Hey! Do you know where my flag is? You might need to put in some effort to find it.";
$a = $_POST['sp1r1t'];
$b = $_POST['2024'];
if(isset($a) && isset($b)){
    create_function($a,bin2hex($b))();
}
7.4.21源码泄露
```

`docker buildx build --platform linux/amd64 -t dionysus13931/hiden:latest -t dionysus13931/hiden:v1 . --push`

### 签到

`rm -rf *`不会删除`.bk.php`等`.`开头的文件

`sudo chattr +i /path/to/your/file`保持index.php不被删除

docker地址`dionysus13931/spirit001:v1`

`docker buildx build --platform linux/amd64 -t dionysus13931/spirit001:latest -t dionysus13931/spirit001:v1 . --push`

### sql+phar

### java
