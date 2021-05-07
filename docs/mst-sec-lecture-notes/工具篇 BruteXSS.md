# 米斯特白帽培训讲义 工具篇 BruteXSS

> 讲师：[gh0stkey](https://www.zhihu.com/people/gh0stkey/answers)

> 整理：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 介绍

BruteXSS 是一个非常强大和快速的跨站点脚本检测工具，可用于暴力注入参数。BruteXSS 从指定的词库加载多种有效载荷进行注入，并且使用指定的载荷和扫描检查这些存在 XSS 漏洞的参数。得益于非常强大的扫描功能，在执行任务时，BruteXSS 非常准确而且极少误报。 BruteXSS 支持 POST 和 GET 请求，并适应现代 Web 应用程序。

特性：

+   XSS 爆破
+   XSS 扫描
+   GET/POST 请求
+   可包含自定义单词
+   人性化的 UI

## 安装

首先安装 Python 2.7。

依赖是`Colorama`和`Mechanize`两个库。但我看到源码中包含了这两个库，所以一般不用自己安装。如果运行失败，那么执行这两条命令手动安装一下。

```
pip install colorama
pip install Mechanize
```

之后从`https://github.com/shawarkhanethicalhacker/BruteXSS/zipball/master`下载所有文件，解压。

还需要单词列表，原版的`wordlist.txt`有 20 条语句，只能执行基本的 XSS 检查。

`https://github.com/ym2011/penetration/blob/master/BruteXSS/wordlist-small.txt`这个文件有 100 条语句，可以执行相对全面的 XSS 检查。

`https://github.com/ym2011/penetration/blob/master/BruteXSS/wordlist-medium.txt`这个文件有 200 条语句，可以执行绕过 WAF 的 XSS 检查。

`https://github.com/ym2011/penetration/blob/master/BruteXSS/wordlist-huge.txt`这个文件有 5000 条语句，可以非常全面并且执行绕过 WAF 的 XSS 检查。

然后为了模拟被测页面，我们还要部署一个页面：

```php
\\XSS反射演示
<form action="" method="get">
    <input type="text" name="xss"/>
    <input type="submit" value="test"/>
</form>
<?php
$xss = @$_GET['xss'];
if($xss!==null){
    echo $xss;
}
```

假设我们能够通过`localhost/xss.php`来访问它。

## 使用

首先在解压处执行：

```
python brutexss.py
```

于是就进入命令行界面了

```
                                                                                
  ____             _        __  ______ ____
 | __ ) _ __ _   _| |_ ___  \ \/ / ___/ ___|
 |  _ \| '__| | | | __/ _ \  \  /\___ \___ \
 | |_) | |  | |_| | ||  __/  /  \ ___) |__) |
 |____/|_|   \__,_|\__\___| /_/\_\____/____/

 User:Gh0stkey
 注意:使用错误的有效载荷的定义
 字典可能给你积极性质
 更好地使用字典
 提供积极的结果。

[?] 选择方法: [G]GET 或者 [P]Post (G/P):
```

下面它会询问我们一些配置。我们在选择方法时输入`G`，指定 URL 时输入`http://localhost/xss.php?xss`，这里一定要把参数暴露出来给它。然后字典位置输入`wordlist.txt`，大家也可以尝试其他字典。

```
[?] 选择方法: [G]GET 或者 [P]Post (G/P): G
[?] 输入 URL:
[?] > http://localhost/xss.php?xss=
[+] 检测 localhost 是可用的...
[+] localhost is available! Good!
[?] 输入字典的位置 (按Enter键使用默认 wordlist.txt)
[?] > wordlist.txt
```

之后程序会显示结果，告知我们该页面存在 XSS 漏洞。

```
[+] 从指定字典加载载荷.....
[+] 25 攻击载荷加载...
[+] Bruteforce开始:
[+] 测试 'xss' 参数...
[+] 0 / 25 攻击载荷注入...
[!] Xss漏洞发现
[!] 参数:       xss
[!] Payload:    </script>"><script>prompt(1)</script>
[+] Bruteforce完成。
[+] 1 参数是 容坠セ鞯?   xss.
[+] 扫描结果 localhost:
+----+------------+----------------+
| Id | Parameters |     Status     |
+----+------------+----------------+
| 0  |    xss     |   Vulnerable   |
+----+------------+----------------+

[?] [E]结束进程\[A]程序初始化
```

之后它会让我们选择，结束进程的意思就是退出，初始化的意思就是重新开始。如果不需要扫描其他东西，我们输入`E`。

如果是 POST 扫描，我们为 URL 输入`http://localhost/xss.php`，为数据输入`xss=`就可以了。

由于一些 XSS 比如储存型 XSS 不便于自动化扫描，这个工具的作用仍然很有限，遇到扫不出来的漏洞很正常。
