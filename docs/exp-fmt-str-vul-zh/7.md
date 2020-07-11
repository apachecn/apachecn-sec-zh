# 七、工具

一旦利用完成，或者甚至在利用开发过程中，使用工具来获取必要的偏移更加有用。一些工具也有主意识别漏洞，例如在闭源软件中的格式化字符串漏洞。我在这里列出了四个工具，它们对我来说很有用，可能对你也是。

## 7.1 `ltrace`，`strace`

`ltrace` [8] 和`strace` [9] 工作方式相似：在程序调用它们时，它们勾住库和系统调用，记录它们的参数和返回值。这让你能够观察程序如何和系统交互，将程序本身看做黑盒。

所有现存的格式化函数都是库调用，并且它们的参数，最重要的是它们的地址都可以使用`ltrace`来观察。任何可以使用`ptrace`的进程中，你都可以使用这个方式快速判断格式化字符串的地址。`strace`用于获取缓冲区地址，数据读入到该地址中，例如如果`read`被调用来读取数据，它们之后又用作格式化字符串。

了解这两个工具的用法，你可以节省大量时间，你也可以使用它们来尝试将 GDB 附加到过时的程序上，它没有任何符号和编译器优化，来寻找两个简单的偏移。

> 译者注：在 Windows 平台上，你可以使用 [SysinternalsSuite](https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx) 来观察文件、注册表和 API 的使用情况。

## 7.2 GDB，`objdump`

GDB [7]，经典的 GNU 调试器，是一个基于文本的调试器，它适用于源码和机器代码级别的调试。虽然它看起来并不舒服，一旦你熟悉了它，它就是程序内部的强大接口。对于任何事情，从调试你的利用，到观察进程被利用，它都非常好用。

`objdump`，一个 GNU 二进制工具包中的程序，适用于从可执行二进制或目标文件中获取任何信息，例如内存布局，区段或`main`函数的反汇编。我们主要使用它来从二进制中获取 GOT 条目的地址。但是它可以以很多不同的方式使用。

> 译者注：这两个工具都在`build-essential`包中，可以执行`apt-get install build-essential`来安装。

> 译者注：在 Windows 平台上，你可以使用 [OllyDbg](http://down.52pojie.cn/Tools/Debuggers/OllyDbg%20v2.01.zip) 或者 WinDbg（[x86](http://down.52pojie.cn/Tools/Debuggers/Windbg_x86_6.12.2.633.rar)，[x64](http://down.52pojie.cn/Tools/Debuggers/Windbg_amd64_6.12.2.633.rar)）来代替 GDB，你可以使用 [IDA Pro](http://down.52pojie.cn/Tools/Disassemblers/IDA%20Pro%20Advanced%205.5%20with%20Hex-Rays%201.1.rar) 来代替`objdump。
