# 米斯特白帽培训讲义 实战篇 迅雷 CMS

> 讲师：[gh0stkey](https://www.zhihu.com/people/gh0stkey/answers)

> 整理：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 站点搜索

关键词：`intext:"技术支持:银川迅雷网络公司"`

另外这个 CMS 是闭源的，没有找到源码。

## Cookie 伪造

起因是这样，我们随便找了一个网站，访问后台登录页面（`/admin/login.asp`），然后使用弱密码`admin:admin`进了后台（`/admin/index.asp`），发现 Cookie 有这样一个东西：

![](http://upload-images.jianshu.io/upload_images/118142-67074c50fcd99f01.jpg)

我们可以看到，用户名称和 ID 是明文保存的。我们猜测，程序根据 Cookie 中的值来判断当前登录用户。于是我们把其中一个删掉，结果退出登录。再次访问后台时返回到了登录页面。

![](http://upload-images.jianshu.io/upload_images/118142-a3bcb670d607ed58.jpg)

这就说明它的确使用 Cookie 中的值来判断。我们再进行试验，将 Cookie 的两个值重新设置，之后直接访问`/admin/index.asp`：

![](http://upload-images.jianshu.io/upload_images/118142-626d398d4a65e851.jpg)

成功进入后台。

