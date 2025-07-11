+++
title = 'ADB 命令使用大全（建议收藏） Android 调试必备'
date = 2025-06-22T14:12:55.080805+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# 基础adb命令



```
# 重启adb 
adb kill-server

# 查看已连接的设备
adb devices

# 进入命令行
adb shell

# 使用 -s 参数来指定设备
adb -s <设备序列号> shell

# 显示日志
adb logcat
```


# 获取 API Level



进入 adb shell ，执行下面命令获取当前 Android 系统的 API Level（即 SDK 版本）：

```
getprop ro.build.version.sdk
```


以下是 **Android 版本与 API Level 的对应表** （截至 Android 15）：

| Android 版本 | API Level | 代号 | 发布时间 |
|--- | --- | --- | ---|
| Android 15 | 35 | Vanilla Ice Cream | 2024年9月 |
| Android 14 | 34 | Upside Down Cake | 2023年10月 |
| Android 13 | 33 | Tiramisu | 2022年8月 |
| Android 12L | 32 |  | 2022年3月 |
| Android 12 | 31 | Snow Cone | 2021年10月 |
| Android 11 | 30 | Red Velvet Cake | 2020年9月 |
| Android 10 | 29 | Q | 2019年9月 |
| Android 9 | 28 | Pie | 2018年8月 |
| Android 8.1 | 27 | Oreo | 2017年12月 |
| Android 8.0 | 26 | Oreo | 2017年8月 |
| Android 7.1 | 25 | Nougat | 2016年10月 |
| Android 7.0 | 24 | Nougat | 2016年8月 |
| Android 6.0 | 23 | Marshmallow | 2015年10月 |
| Android 5.1 | 22 | Lollipop | 2015年3月 |
| Android 5.0 | 21 | Lollipop | 2014年11月 |


# 获取 apk 安装路径



获取指定包名的 APK 路径

```
adb shell pm path com.shizhuang.duapp

package:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk
```


将 APK 文件拉取到本地

```
adb pull /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk
```


# 获取 Activity 信息



进入 adb shell 

```
# 获取设备上当前运行的 Activity
dumpsys activity activities | grep "mResumedActivity"

# 获取活动栈中的所有 Activity，并从中提取出最近的 5 个 Activity
dumpsys activity activities | grep "Hist #" | head -n 5
```


# 获取当前应用包名



Mac/Linux：

```
adb shell dumpsys activity activities | grep "mResumedActivity"
```
Windows：

```
adb shell dumpsys activity activities | findstr "mResumedActivity"
```


调用实例：

```
(base) PS D:\test> adb shell dumpsys activity activities | findstr "mResumedActivity"
    mResumedActivity: ActivityRecord{b40059e u0 com.shizhuang.duapp/.du_login.optimize.LoginContainerActivityV2 t110}
```
其中 com.shizhuang.duapp 就是当前应用的包名



# 获取进程信息



```
# 显示当前系统中正在运行的进程信息、CPU、内存使用率等
top

# 列出当前所有进程
ps -A

# 列出名称包含 fs 的进程
ps -A | grep fs

# 获取 1234 端口进程的 pid
lsof | grep 1234

# 根据包名获取 pid
pidof com.shizhuang.duapp

# 查看进程状态(如果 TracerPid>0 表示被调试状态，TracerPid 就是跟踪调试的 进程id)
cat /proc/pid/status
```


# 进程管理



```
# 停止指定进程 
kill pid

# 强制停止指定进程
kill -9 pid

# 暂停进程
kill -19 pid

# 继续进程
kill -18 pid
```


# 文件管理



```
# 拉取文件/目录到本地
adb pull /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ== D:\temp

# 使用cat命令查看文件的内容
cat filename.txt

# 当目录不存在自动创建目录
mkdir -p /sdcard/dump_dex

# 复制文件（目录必须存在）
cp /data/data/com.shizhuang.duapp/8681372.dex /sdcard/dump_dex

# 复制文件并自动创建目录
mkdir -p /sdcard/dump_dex && cp /data/data/com.shizhuang.duapp/8681372.dex /sdcard/dump_dex/

# 移动文件
mv /data/data/com.shizhuang.duapp/8681372.dex /sdcard/dump_dex
```


# 删除文件/目录



删除单个文件：

```
rm file.txt
```


删除多个文件：

```
rm file1.txt file2.log
```


删除所有 txt 文件

```
rm mydir/*.txt
```


删除空目录（只能删除空目录）：

```
rmdir mydir/
```


删除整个目录及其内容，可以使用下面的命令：

```
rm -r mydir
```


如果你想更安全些，可以加 -i，逐个确认：

```
rm -ri mydir
```


如果你要强制删除，不显示任何提示，可以用：

```
rm -rf mydir
```


# 查找文件/目录



查找 /data 路径下所有名字包含 com.cyrus.example 的文件或目录

```
 find /data -iname '*com.cyrus.example*'
```


# 查找包含指定内容的文件



```
grep -rl "关键字" .
```
参数说明：

- grep: 文本搜索工具

- -r: 递归查找目录下的所有文件

- -l: 只输出匹配的文件名（不输出匹配内容）

- "关键字": 你要查找的字符串

- .: 当前目录



示例：

```
wayne:/data/data/com.cyrus.example/cyrus # grep -rl "ba0.g" .
./1437648_class_list_execute.txt
./1437648_class_list.txt
./1437648_ins_12347.bin
./1437648_ins_13638.bin
```


如需过滤特定文件类型（例如只查 .txt）：

```
wayne:/data/data/com.cyrus.example/cyrus # grep -r "ba0.g" *.txt
1437648_class_list.txt:Lba0/g;
1437648_class_list_execute.txt:Lba0/g;
```


# 查看文件详细信息



通过 adb shell 进入命令行通过 ls -alh 查看当前路径下所有文件。

```
wayne:/sdcard # ls -alh
total 32M
drwxrwx--x 15 root sdcard_rw 3.4K 2024-09-23 17:52 .
drwx--x--x  3 root sdcard_rw 3.4K 2024-09-16 18:43 ..
-rw-rw----  1 root sdcard_rw   88 2024-09-18 12:03 .thumbcache_idx_001
drwxrwx--x  2 root sdcard_rw 3.4K 2024-09-16 18:43 Alarms
drwxrwx--x  5 root sdcard_rw 3.4K 2024-09-18 00:25 Android
```


通过 stat 命令查看更加详细的文件信息，包括访问时间、修改时间、文件类型和 inode 号等。

```
wayne:/sdcard # stat /sdcard/Android
  File: /sdcard/Android
  Size: 3488     Blocks: 7       IO Blocks: 512 directory
Device: 1ch/28d  Inode: 2999     Links: 5
Access: (0771/drwxrwx--x)       Uid: (    0/    root)   Gid: ( 1015/sdcard_rw)
Access: 2024-09-16 18:43:38.453334673 +0800
Modify: 2024-09-18 00:25:03.481711645 +0800
Change: 2024-09-18 00:25:03.481711645 +0800
```


通过 file 命令查看文件类型

```
wayne:/sdcard # file Magisk-v27.0.apk
Magisk-v27.0.apk: Zip archive data
```


head 用于查看文本文件的前几行内容，默认是前 10 行。

```
wayne:/sdcard # head /proc/cpuinfo
Processor       : AArch64 Processor rev 4 (aarch64)
processor       : 0
BogoMIPS        : 38.00
Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32
CPU implementer : 0x51
CPU architecture: 8
CPU variant     : 0xa
CPU part        : 0x801
CPU revision    : 4
```


-n \<行数>：指定要显示的行数。

```
wayne:/sdcard # head -n 5 /system/build.prop

# begin common build properties
# autogenerated by build/make/tools/buildinfo_common.sh
ro.system.build.date=Mon Sep 16 18:43:25 CST 2024
ro.system.build.date.utc=1726483405
```


# 编辑文件



编辑文件

```
vim a.log
```
如果文件不存在，vim 会创建一个新的。



打开后，你默认处于 “普通模式” ，此时按：

```
i
```
此时屏幕左下角会显示 -- INSERT --，表示你现在可以开始输入内容。



按下 Esc 键即可退出插入模式，回到普通模式。



在普通模式下，输入以下命令退出 vim

```
:wq   ↵   # 保存并退出
:q!   ↵   # 不保存直接退出
```


其他常用命令：

| 操作 | 命令（普通模式） |
|--- | ---|
| 插入（光标前） | i |
| 插入（新行） | o |
| 删除整行 | dd |
| 撤销 | u |
| 保存但不退出 | :w + Enter |
| 不保存强制退出 | :q! + Enter |
| 移动光标上下左右 | 使用方向键或 h j k l |


# 截图



```
# 截图
adb shell screencap /sdcard/screenshot.png
# 将截图从设备复制到电脑
adb pull /sdcard/screenshot.png
# 删除设备中的截图文件
adb shell rm /sdcard/screenshot.png
```


# Logcat



## 1. 过滤出 Error 日志（E级别）



```
adb logcat *:E
```
日志优先级从低到高依次为：

- V - Verbose

- D - Debug

- I - Info

- W - Warn

- E - Error

- F - Fatal

- S - Silent (屏蔽所有日志)



## 2. 过滤指定包名的日志



先启动app 再执行下面的命令

```
adb logcat --pid=$(adb shell pidof com.cyrus.example)
```


## 3. 过滤包含指定字符串的日志



linux / mac：

```
adb logcat | grep "关键字"
```


windows：

```
adb logcat | Select-String "关键字"
```


## 4. 按 Tag 和 Level 过滤

```
adb logcat System.err:D *:S
```
表示只显示 System.err 的 Debug 日志，其他 tag 的都不显示。



说明：

- 第一个参数指定 System.err:D，设置该 tag 日志级别为 D（Debug）

- 第二个参数 *:S 把其他所有 tag 的日志设为 Silent



## 5. 清空日志缓存

```
adb logcat -c
```


## 6. 输出日志到文件

```
adb logcat -v time > logcat.txt
```
- -v time：显示时间戳（还有 brief, process, tag, raw, threadtime, long）

- 输出保存到文件中



## 7. 结合多种过滤方式



举例：过滤包名为 com.cyrus.example 的 Error 级别日志，并包含字符串 Exception：

```
adb logcat --pid=$(adb shell pidof com.cyrus.example) *:E | grep "Exception"
```


windows：

```
adb logcat --pid=$(adb shell pidof com.cyrus.example) *:E | Select-String "Exception"
```


# /proc/self/maps



/proc/self/maps 是 Linux（含 Android）系统中一个非常重要的伪文件，它提供了当前进程内存映射（memory mapping）信息，是分析当前进程加载了哪些资源的重要窗口。



包括：

- 加载的 .so 动态库

- 加载的 .dex 文件（包含 ODEX / VDEX）

- 映射的 Java 堆、native 堆、stack 等

- 匿名 mmap 内存区域

- JIT 编译生成的代码段

- 映射的 /system/, /data/, /apex/, /dev/ashmem 等文件



进入 adb shell 执行下面命令读取 maps

```
cat /proc/$(pidof <packageName>)/maps
```


示例：

```
wayne:/ # cat /proc/$(pidof com.shizhuang.duapp)/maps | grep GameVMP
7b6ae7c000-7b6ae7d000 r--p 0001d000 103:20 19266                         /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/lib/arm64/libGameVMP.so
7b6ae7d000-7b6ae7f000 rw-p 0001e000 103:20 19266                         /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/lib/arm64/libGameVMP.so
```






