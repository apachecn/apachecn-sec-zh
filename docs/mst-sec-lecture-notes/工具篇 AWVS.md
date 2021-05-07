# 米斯特白帽培训讲义 工具篇 AWVS

> 讲师：[gh0stkey](https://www.zhihu.com/people/gh0stkey/answers)

> 整理：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 功能

AWVS 即 Acunetix Web Vulnerability Scanner 是一个网站及服务器漏洞扫描软件。

![](http://ww1.sinaimg.cn/large/841aea59jw1faynwuq2u2j20s10j7q54.jpg)

+   自动的客户端脚本分析器，允许对 Ajax 和 Web 2.0 应用程序进行安全性测试。
+   业内最先进且深入的 SQL 注入和跨站脚本测试
+   高级渗透测试工具，例如 HTTP Editor 和 HTTP Fuzzer
+   可视化宏记录器帮助您轻松测试 web 表格和受密码保护的区域
+   支持含有 CAPTHCA 的页面，单个开始指令和 Two Factor（双因素）验证机制
+   丰富的报告功能，包括 VISA PCI 依从性报告
+   高速的多线程扫描器轻松检索成千上万个页面
+   智能爬行程序检测 web 服务器类型和应用程序语言
+   Acunetix 检索并分析网站，包括 flash 内容、SOAP 和 AJAX
+   端口扫描 web 服务器并对在服务器上运行的网络服务执行安全检查

## 下载和安装

演示中使用的是 AWVS 10 版本，请在[这里](http://www.freebuf.com/sectool/71091.html)下载。

安装部分主要分为两个步骤：安装主程序和打破解补丁。这款工具是由吾爱破解亲自操刀来破解的。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynwylc7xj20pw066q34.jpg)

我们打开安装文件之后，依次点击“下一步”就可以了。

![](http://ww1.sinaimg.cn/large/841aea59jw1faynx2518zj20rt0kttaj.jpg)

安装完毕之后，打开破解补丁，破解补丁是全自动的，等到出现这个界面，就说明破解完成了。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynx59z0tj20j10e5mxr.jpg)

## 基本使用

![](http://ww2.sinaimg.cn/large/841aea59jw1faynx91hk7j20os0clmxn.jpg)

首先，打开程序主界面：

![](http://ww3.sinaimg.cn/large/841aea59jw1faynxby5l2j20sv0jsacl.jpg)

点击左上角的`Scan`按钮，会弹出一个窗口，我们将其中的`Website URL`改为百度的 URL。这里我们拿百度主页来演示。

![](http://ww3.sinaimg.cn/large/841aea59jw1faynxfl2oaj20st0jq0us.jpg)

之后我们只需要连续点击下一步，跳过`Option`界面。我们可以看到`Target`界面为我们提供了一些信息，比如服务器版本。我们也可以按需选择服务器所使用的环境。

![](http://ww1.sinaimg.cn/large/841aea59jw1faynxis9oaj20o10irmyl.jpg)

点击下一步之后，我们来到了`Login`界面，这里我们可以设置登录所需的凭证。我们这里先保留默认。

![](http://ww1.sinaimg.cn/large/841aea59jw1faynxneoa8j20nx0ivabo.jpg)

再点击下一步，等待一下，然后就开始了。扫描完成之后，我们再来看主界面。

![](http://ww3.sinaimg.cn/large/841aea59jw1faynxva2gkj21c40qptci.jpg)

`Web Alerts`中会提示存在的漏洞。`Site Structure`中会显示站点结构。我们随便选择一个漏洞看一下。它提示了站点中有一个 CSRF 漏洞。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynxyf2zoj216x0letbi.jpg)

这里就有可能是个误报，虽然 AWVS 很强大，但是误报也是很常见的。大家以后碰到的时候无视它就好了。

## 登录后的扫描

![](http://ww1.sinaimg.cn/large/841aea59jw1fayny2a5qwj20lt0ex0tf.jpg)

就是在`Login`界面的`Form Authentication`分组框中输入所需的Cookie。我们点击旁边的“新建”按钮（一张纸的图标），在弹出来的窗口中登录网站，来创建登录凭证。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynype4uqj20zn0pnwg0.jpg)

登录完毕之后点击右下角的`Finish`，然后会弹出来一个文件选择框，保存文件即可。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynyvhgyjj217h0qqn00.jpg)

之后我们点击旁边的“打开”按钮（文件夹的图标），选择刚刚保存的文件，并点击`Next`。这样我们就能执行登录状态下的扫描了。

## 批量扫描

思路来自：<http://zone.wooyun.org/content/20325>。

利用 AWVS 会采集目标站点的外链的特点，达到批量扫描的效果。

![](http://ww1.sinaimg.cn/large/841aea59jw1faynz1ggxyj21220g0q5a.jpg)

比如，我们可以创建一个 HTML 文件，里面包含要扫描的全部链接，比如我们要扫描谷歌、百度、优酷以及其他网站，我们就可以新建一个`4.html`，内容为：

```html
<a href="http://www.google.com">test</a>
<a href="http://www.baidu.com">test</a>
<a href="http://www.youku.com">test</a>
...
```

然后将这个页面在本地部署，假设，我们可以通过`http://localhost/subject/4.html`访问。然后将其填写到`Website URL`中。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynz5lar8j20nw0ip75t.jpg)

一直点击“下一步”，直到`Finish`界面，我们可以看到，我们指定的站点全部出现在下方的列表框中，我们把他们全部勾选。之后点击`Finish`按钮开始批量扫描。

![](http://ww4.sinaimg.cn/large/841aea59jw1faynzdo6m5j20o20ivabr.jpg)
