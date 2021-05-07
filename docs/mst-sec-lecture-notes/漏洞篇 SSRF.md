# 米斯特白帽培训讲义 漏洞篇 SSRF

> 讲师：[gh0stkey](https://www.zhihu.com/people/gh0stkey/answers)

> 整理：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

很多 Web 应用都提供了从其他服务器上获取数据的功能。使用用户指定的 URL，web 应用可以获取图片，下载文件，读取文件内容等。这个功能如果被恶意使用，可以利用存在缺陷的 Web 应用作为代理，攻击远程和本地服务器。这种形式的攻击成为服务器请求伪造（SSRF）。

## 原理

```php
<?php
$url = @$_GET['url'];
if($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    $co = curl_exec($ch);
    curl_close($ch);
    echo $co;
}
```

这段代码从 URL 中读取`url`参数，之后访问`url`参数所指向的 URL 资源，最后把资源显示在页面上。（当然这个代码有些简陋了，不是真正的代理，有些资源可能处理不好。）

我们将其保存为`ssrf.php`并部署。之后我们访问`localhost/ssrf.php?url=http://www.baidu.com`：

![](http://upload-images.jianshu.io/upload_images/118142-c5d7c31d19df5908.jpg)

可以看到显示正常。这个漏洞还可以用于访问本地的图片，我们再访问`file:///C:/Windows/win.ini`：

![](http://upload-images.jianshu.io/upload_images/118142-44dc1d7ebd79a0a4.jpg)

页面上是乱的，但是我们查看源代码，也可以正常显示。

## 利用

可以对服务器所在内网以及本地进行端口扫描，获取服务的指纹信息。指纹识别通过访问默认文件来实现：

![](http://upload-images.jianshu.io/upload_images/118142-1e6000ba381b655e.jpg)

这张图中，我们访问了`10.50.33.43`的 Tomcat 服务的默认文件。`10.50.33.43`是内网，我们直接访问是访问不了的，但是通过 SSRF 就可以。并且，我们通过访问 Tomcat 的默认文件确定了这台机子上部署了 Tomcat 服务。

确定了所部署的服务之后，我们就可以有针对性的攻击内网部署的应用。比如 ST2 和 SQL 注入这种通过 GET 方法实施的攻击。

我们还可以利用该漏洞读取服务器中的配置文件，比如上面的`win.ini`。

## 挖掘

以下业务场景容易出现这种漏洞：

1.  应用从用户指定的 URL 获取图片，然后把它用一个随机名称保存在硬盘上，并展示给用户：

2.  应用获取用户指定 URL 的数据（文件或者 HTML）。这个函数会使用 socket 和 服务器建立 TCP 连接，传输原始数据。

3.  应用根据用户提供的 URL，抓取用户的 Web 站点，并且自动生成移动 Wap 站。

4.  应用提供测速功能，能够根据用户提供的 URL，访问目标站点，以获取其在对应经纬度的访问速度。

### Web 功能

我们从上面的概述可以看出，SSRF 是由于服务端获取其它服务器的相关信息的功能中形成的，因此我们可以列举几种在 Web 应用中，常见的从服务端获取其它服务端信息的功能。

1）分享：通过 URL 分享网页内容

早期分享应用，为了更好地提供用户体验，WEB 应用在分享功能汇总，通过会获取目标 URL 地址网页内容中的`<title>`标签或者`<meta name="description" />`标签中的文本内容，作为显示，来提供更好的用户体验。例如，人人网分享功能中：

![](http://p6.qhimg.com/t014393fd344f62b61d.png)

```
http://widget.renren.com/****?resourceUrl=****
```

通过目标 URL 地址获取了`title`标签和相关文本内容。如果在此功能中没有对目标地址范围做过滤与限制，就存在 SSRF 漏洞。

根据这个功能，我们可以发现许多互联网公司都有这样的功能，下面是我们从百度分享集成的截图，如下：

![](http://p1.qhimg.com/t016ed3285f68a3cd9e.png)

从国内某漏洞提交平台上提交的 SSRF 漏洞，可以发现包括淘宝、百度、新浪等国内知名公司都曾发现过分享功能上存在 SSRF 漏洞。

2）转码服务：通过 URL 地址把原地址的网页内容调优使其适合手机屏幕浏览

由于手机屏幕大小的关系，直接浏览网页内容时会造成许多不便，因此有些公司提供了转码功能，把网页内容通过相关手段转为适合手机屏幕浏览的演示。例如百度、腾讯、搜狗等公司都提供在线转码服务。

3）在线翻译：通过 URL 地址翻译对应文本的内容。提供此功能的国内公司有百度、有道等

4）图片加载与下载：通过 URL 地址加载或下载图片

此功能用到的地方很多，但大多比较隐秘，比如有些公司加载自家图片服务器上的图片用于展示。（有些公司会把外站图片转存到自家服务器，所以在 HTTP 读取图片时就可能造成 SSRF 问题。）

5）图片、文章收藏功能

此处的文章收藏类似于分享功能中获取 URL 地址中的标题以及内容作为显示，目的还是为了更好的用户体验。图片收藏就类似于图片加载。

6）未公开的 API 实现以及其他调用 URL 的功能

此处类似的功能有 360 提供的网站评分，以及有些网站通过 API 获取远程地址 XML 文件来加载内容。

这些功能中除了分宜和转换服务为公共服务，其他功能均有可能在企业应用开发过程中遇到。

### URL 关键词寻找

根据对存在 SSRF 漏洞的 URL 地址特征的观察，通过我一段时间的手机，大致有一下关键字：

+   share
+   wap
+   url
+   image
+   link
+   src
+   source
+   target
+   u
+   3g
+   display
+   sourceUrl
+   imageUrl
+   domain

如果利用 google 语法（`inurl:url=`）加上这些关键字去寻找 SSRF 漏洞，耐心的验证，现在还是可以找到存在的 SSRF 漏洞。

### 漏洞验证

例如：

```
http://www.douban.com/***/service?image=http://www.baidu.com/img/bd_logo1.png
```

排除法一：

你可以直接右键图片，在新窗口打开图片，如果浏览器上 URL 地址栏中是`http://www.baidu.com/img/bd_logo1.png`，则不存在 SSRF。

排除法二：

你可以使用 Burp 等抓包工具来判断是否是 SSRF，首先 SSRF 是由服务端发起的请求，因此在加载图片的时候，是由服务端发起的，所以我们本地浏览器中的请求就不应该存在图片的请求，在此例子中，如果刷新当前页面，有如下请求，则可判断不是 SSRF。

![](http://p9.qhimg.com/t01554ac9cba1ae96e9.png)

比如，图片是百度上的，你调用的是搜狗，浏览器向百度请求图片，那么就不存在 SSRF 漏洞。如果浏览器向搜狗请求图片，那么就说明搜狗服务器发送了请求，向百度请求图片，可能存在 SSRF。

此处说明下，为什么这边用排除法来判断是否存在 SSRF。举个例子：

![](http://p2.qhimg.com/t01080058bb303b1e6f.png)

现在大多数修复 SSRF 的方法基本都是区分内外网来做限制。如果我们请求：

```
http://read.******.com/image?umageUrl=http://10.10.10.1/favicon.ico
```

而没有内容显示，我们就无法判断此处不存在 SSRF，或者`http://10.10.10.1/favicon.ico`被过滤了，还是根本就没有这个图片。因为我们事先不知道这个地址的文件是否存在，我们判断不出是哪个原因，所以使用排除法。

实例验证：

经过简单的排除验证之后，我们就要验证看看此URL是否可以来请求对应的内网地址。在此例子中，首先我们要获取内网存在HTTP服务且存在favicon.ico文件的地址，才能验证是否是SSRF漏洞。

找存在HTTP服务的内网地址：

一、从漏洞平台中的历史漏洞寻找泄漏的存在web应用内网地址

二、通过二级域名暴力猜解工具模糊猜测内网地址

![](http://p0.qhimg.com/t01111bbf7ba9e818bc.png)

```
example:ping xx.xx.com.cn
```

可以推测`10.215.x.x`此段就有很大的可能：`http://10.215.x.x/favicon.ico`存在。

再举一个特殊的例子来说明：

```
http://fanyi.baidu.com/transpage?query=http://www.baidu.com/s?wd=ip&source=url&ie=utf8&from=auto&to=zh&render=1
```

此处得到的IP 不是我所在地址使用的IP，因此可以判断此处是由服务器发起的`http://www.baidu.com/s?wd=ip`请求得到的地址，自然是内部逻辑中发起请求的服务器的外网地址（为什么这么说呢，因为发起的请求的不一定是fanyi.baidu.com，而是内部其他服务器）,那么此处是不是SSRF，能形成危害吗？  严格来说此处是SSRF，但是百度已经做过了过滤处理，因此形成不了探测内网的危害。

## 防御

通常有一下 5 个思路：

1.  过滤返回信息，验证远程服务器对请求的相应，是比较容易的方法。如果 Web 应用获取某种类型的文件，那么可以在把返回结果展示给用户之前先验证返回信息是否符合标准。

2.  统一错误信息，避免用户根据错误信息来判断远程服务器端口状态。

3.  限制请求的端口为 HTTP 常用端口，比如 80、443、8080、8090。

4.  黑名单内网 IP，避免应用被用来获取内网数据，攻击内网。

5.  禁用不需要的协议。仅仅允许 HTTP 和 HTTPS 请求。可以防止类似于`file://`、`gopher://`和`ftp://`等引起的问题。

## 绕过

### URL

```
http://username:password@www.xxx.com:80/
 |       |       |        |           |
协议   用户名   密码     主机        端口
```

所以我们就可以使用这个格式来绕过：

```
http://www.baidu.com@www.qq.com/
```

### IP 转换

转为数字：

```
127.0.0.1
```

转为十六进制：

```
0x7F.0x00.0x00.0x01
0x7F000001
```

转为八进制；

```
0177.0000.0000.0001
```

```
C:\Users\asus\Desktop> ping 0x7F.0x00.0x00.0x01

正在 Ping 127.0.0.1 具有 32 字节的数据:
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128

127.0.0.1 的 Ping 统计信息:
    数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms
C:\Users\asus\Desktop> ping 0x7F000001

正在 Ping 127.0.0.1 具有 32 字节的数据:
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128

127.0.0.1 的 Ping 统计信息:
    数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms
C:\Users\asus\Desktop> ping 0177.0000.0000.0001

正在 Ping 127.0.0.1 具有 32 字节的数据:
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128

127.0.0.1 的 Ping 统计信息:
    数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms
```

### URL 跳转

```
<?php header("Location: $_GET['url']"); ?>
```

保存为`urllocation.php`然后部署，之后可以用`http://<host>/urllocation.php?url=<url>`来跳转。

### 短网址

百度：<http://dwz.cn/>

### [xip.io](http://xip.io)

```
            gg                       gg
            ""                       ""
,gg,   ,gg  gg   gg,gggg,            gg     ,ggggg,
 ""8b,dP"   88   I8P"  "Yb           88    dP"  "Y8ggg
   ,88"     88   I8'    ,8i          88   i8'    ,8I
 ,dP"Y8,  _,88,_,I8 _  ,d8'   d8b  _,88,_,d8,   ,d8'
dP"   "Y888P""Y8PI8 YY88888P  Y8P  8P""Y8P"Y8888P"
                 I8
                 I8    wildcard DNS for everyone 
                 ""
    
What is xip.io?
xip.io is a magic domain name that provides wildcard DNS
for any IP address. Say your LAN IP address is 10.0.0.1.
Using xip.io,

          10.0.0.1.xip.io   resolves to   10.0.0.1
      www.10.0.0.1.xip.io   resolves to   10.0.0.1
   mysite.10.0.0.1.xip.io   resolves to   10.0.0.1
  foo.bar.10.0.0.1.xip.io   resolves to   10.0.0.1

...and so on. You can use these domains to access virtual
hosts on your development web server from devices on your
local network, like iPads, iPhones, and other computers.
No configuration required!
    
How does it work?
xip.io runs a custom DNS server on the public Internet.
When your computer looks up a xip.io domain, the xip.io
DNS server extracts the IP address from the domain and
sends it back in the response.
    
Does xip.io cost anything?
Nope! xip.io is a free service from Basecamp, the
creators of Pow. We were tired of jumping through hoops
to test our apps on other devices and decided to solve
the problem once and for all.
    
© 2012-2014 Sam Stephenson, Basecamp
```

## 附录

+   [SSRF漏洞的挖掘经验](https://www.sobug.com/article/detail/11)

