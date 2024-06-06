---
title: GFCTF-2021-代码审计
date: 2023-08-15 23:52:15
categories:
- 网络安全
tags:
- web 
description: |
    马上就删
---
开局是一个Apache任意文件读取漏洞

```php
<?php
error_reporting(0);
define("main","main");
include "Class.php";
$temp = new Temp($_POST);
$temp->display($_GET['filename']);

?>

```

```php
//Class.php
<?php
defined('main') or die("no!!");
Class Temp{
    private $date=['version'=>'1.0','img'=>'https://www.apache.org/img/asf-estd-1999-logo.jpg'];
    private $template;
    public function __construct($data){

        $this->date = array_merge($this->date,$data);
    }
    public function getTempName($template,$dir){
        if($dir === 'admin'){
            $this->template = str_replace('..','','./template/admin/'.$template);
            if(!is_file($this->template)){
                die("no!!");
            }
        }
        else{
            $this->template = './template/index.html';
        }
    }
    public function display($template,$space=''){

        extract($this->date);
        $this->getTempName($template,$space);
        include($this->template);
    }
    public function listdata($_params){
        $system = [
            'db' => '',
            'app' => '',
            'num' => '',
            'sum' => '',
            'form' => '',
            'page' => '',
            'site' => '',
            'flag' => '',
            'not_flag' => '',
            'show_flag' => '',
            'more' => '',
            'catid' => '',
            'field' => '',
            'order' => '',
            'space' => '',
            'table' => '',
            'table_site' => '',
            'total' => '',
            'join' => '',
            'on' => '',
            'action' => '',
            'return' => '',
            'sbpage' => '',
            'module' => '',
            'urlrule' => '',
            'pagesize' => '',
            'pagefile' => '',
        ];

        $param = $where = [];

        $_params = trim($_params);

        $params = explode(' ', $_params);
        if (in_array($params[0], ['list','function'])) {
            $params[0] = 'action='.$params[0];
        }
        foreach ($params as $t) {
            $var = substr($t, 0, strpos($t, '='));
            $val = substr($t, strpos($t, '=') + 1);
            if (!$var) {
                continue;
            }
            if (isset($system[$var])) { 
                $system[$var] = $val;
            } else {
                $param[$var] = $val; 
            }
        }
        // action
        switch ($system['action']) {

            case 'function':

                if (!isset($param['name'])) {
                    return  'hacker!!';
                } elseif (!function_exists($param['name'])) {
                    return 'hacker!!';
                }

                $force = $param['force'];
                if (!$force) {
                    $p = [];
                    foreach ($param as $var => $t) {
                        if (strpos($var, 'param') === 0) {
                            $n = intval(substr($var, 5));
                            $p[$n] = $t;
                        }
                    }
                    if ($p) {

                        $rt = call_user_func_array($param['name'], $p);
                    } else {
                        $rt = call_user_func($param['name']);
                    }
                    return $rt;
                }else{
                    return null;
                }
            case 'list':
                return json_encode($this->date);
        }
        return null;
    }
}
```

所以要在index.php下传入post数据

```php

public function __construct($data){

    $this->date = array_merge($this->date,$data);
}
public function display($template,$space=''){

    extract($this->date);
    $this->getTempName($template,$space);
    include($this->template);
}
```

这里会把post数据传入extract函数

```php
public function listdata($_params){
    ...
    $_params = trim($_params);
    $params = explode(' ', $_params);
    ...
}
```

这里是重点
访问`t*/admin`路由会发现参数就是post的数据

那么`space=admin&mod=11111 name=phpinfo action=function`就可以被解析

用方法二比较简单 不需要`$p`的逻辑

总结:代码审计狗都不审
