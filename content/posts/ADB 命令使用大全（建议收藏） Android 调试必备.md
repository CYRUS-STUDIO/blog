+++
title = 'ADB 命令使用大全（建议收藏） Android 调试必备'
date = 2025-07-17T19:14:56.354230+08:00
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


# 将一段文本传输到 Android 设备



使用 adb shell 'echo ... > 文件'

```
adb shell 'echo "https://abc.com" > /sdcard/temp.txt'
```


设备上打开 /sdcard/temp.txt



![word/media/image1.png](data:image/png;base64,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rFmzXArG3n77bb311lt223x8fLRo0SJFR0d75DMDAACAhoE1OP4X4QbMrqSkRB999JFuvPHGKocbkrRmzRrdeOON+u9//1vjseTl5Wnbtm0aM2ZMlcINSfruu+90//33KysrS9KZy0BefPFFPfLIIy6HG5KUn5+vadOm6X/+539UXFxcpTGUl5WVpW+//Vbjxo1zOdyQpMzMTD3zzDN67rnn7M42qe+aNWumxx57zGH76tWr9csvv1RaJykpSe+8847D9nvvvVfR0dHVGiMAAABQioBDhBswv+LiYr3wwguaNm1ajb7MFxcX63/+53/0xRdf1Gg8y5Yt0x133KGMjIxqPX7r1q168cUX9ffff+vf//63Pvnkk2qP5dtvv9XcuXOr/XhJmj9/vv7f//t/1X78woUL9corr8gwzDdhbvDgwYqPj3fYPn36dBUWFjqtMXv2bIcBT6dOnTR+/PgajREAAACQCDgIN2B6hmHotdde02effea2mlOmTLG7VoarVq5cqfz8/BqNYfHixZo0aZIWLVpUozqS9NZbb+nQoUPVfvwff/xR4zF8+umn+vnnn2tcxxMeeughNW/e3G7bnj179PXXXzt87IYNG/Tdd985bH/sscdYlBUAAABu0agXGSXcQG275JJL1L17d5tjW7du1U8//WS3/9ChQ9WvX78KxwMDAx2e46uvvtKHH37odBwDBw7UoEGD1LJlS506dUrHjh3TqlWrtGPHDoePefnllzV37lydddZZTmu7olevXurVq5fCwsJUUlKi1NRUrV69WkeOHHH6uGXLllU41rNnT11wwQUKCQnR6dOnlZKSojVr1thdaLKsb775Rg8//HCNnkepjh07qn///goLC1OTJk2Ulpam1atX6/Dhw04f9+abb2rQoEG1stNLbb7XWrdurYkTJ2rq1Kl2a82cOVOXXHKJQkJCbI4XFRVp+vTpDsd89dVXa9CgQXX2PAAAANCwNdqAo7JwQ5JSU1N18cUX19GIXFOTX9VR9y655JIKx3x9fR1+WTv//PM1btw4l+sfOXJEL7/8ssP2jh07aurUqerdu3eFtnvuuUdLly7VU089ZXe2xR9//KEffvhBV199tcvjKa937956/PHH1a1btwoLUU6ePFnffvutXnjhBZfWp4iMjNQzzzyj/v37V6hVVFSkn376SVOnTnV4ucS3336rCRMm1Gixz/bt2+upp55SXFxchYVLJ0+erNWrV2vq1KkOL81JTk7W559/7nAx05qo7ffatddeq8WLF2vTpk0V2jIzM/XBBx9o0qRJNse/++47bdu2zW695s2ba8KECRWO1/bzAAAAQMPVKC9RcSXcAMzg/ffft7tNqXQmEJgzZ47dcEOSvLy8NGLECE2bNs1h/QULFlR73Yhhw4bp7bffVmxsrN1dNpo2bapRo0Y5nBVQ1tlnn6233npLAwYMsFvL19dX8fHxeu655xzWSEtLq9IipeX17t1bH3zwgQYMGGB3VxYfHx8NGzZM8+bNczpD4/PPPzflgqNnnXWW0wVH33vvPZvtXLOyshzumiJJkyZNUuvWrd06RgAAADRujS7gINxAQ3H06FEtWLDAYfuUKVNc+gI5dOhQDR8+3G7b9u3bnV7G4khISIiefPJJNWvWrNK+l19+eaU7aDz99NM655xzKq01YsQIRUZGOmxPTEystIY9FotFzz77rFq2bFlp3+joaD355JMO21NSUrRly5ZqjcPTYmNjnc4+mTVrljUQmz9/vtLT0+3269Onj6655ppaGSMAAAAar0YXcAANxYoVKxy2DR06VBdccIFLdby8vDRq1CiH7WvXrq3y2AYOHOjyr/M+Pj4aPHiww/a2bdu6fKmYj4+P0+ednZ3tUp3yhg8fXqVtTC+77DJ17NjRYfuaNWuqNY764I477lDbtm3tti1ZskTr1q3T/v37NWfOHIc1HnvsMbes7QIAAACU1egCjvvvv1/33Xefp4cB1Njy5csdtl177bVVqtW7d2/5+vrabUtISKhSrepo06aNw7bhw4eradOmLtcKCwtz2Obocp7KVHXdDl9fX914440O2x2tS2EGzZs31yOPPOKwffr06U4XFr3zzjvVrVu32hgaAAAAGrlGF3BIhBwwv7y8PG3YsMFhe58+fapUz9/fX+eff77dtg0bNtT6mhHOLmWxt96FM87Wvzh58mSVatVEXFycw7bNmzfXeBtdTxo+fLjDy5p27tzpcHZRZGSkbrvtttocGgAAABqxRruLyv333y9JTtfjiIiI0EcffeT0F2HAE5xtidqjRw81b968yjUdzaIoLCxUenq6IiIiqlyzMevYsaMsFovDXV1SU1OrdNlLfeLl5aXJkydr7dq1Dp+fPY8++mi13psAAACAKxptwCFVHnKkpKRo3LhxhByod/766y+HbSkpKdX6ldzZApx1OfOhofDx8VGPHj20ceNGu+3VvVymvoiKitKECROcblNc1siRIzV06NBaHhUAAAAas0YdcEiEHDCnrKwsh20ZGRnKyMhw6/nMfDmFJ4WGhjpsawiv6ejRo/X9999r586dTvtZLBY9/PqrHagAACAASURBVPDDdrf4BQAAANylUa7BUV5la3KUhhxpaWl1OCrAsVOnTtXp+RrCl3FPCAwMdNhWUFBQhyOpHRaLxemCo6UmTJigqKioOhgRAAAAGjMCjv9FyAEzKS4urtPzGYZRp+drKJztvvL333/X4Uhqj7PLpUqlpqbWwUgAAADQ2BFwlEHIAbPw8Wn0V5eZgrN1Nvz8/OpwJLUjIyNDr7/+eqX9Pv74Y23evLkORgQAAIDGjG9J5bAmB8zA2U4UF198sUaPHu3W88XExLi1XmORnZ3tsM3Z1rhm8Z///MflwPell17SBx98IIvFUsujAgAAQGNFwGEHIQfqO2cBh2EYGjx4cB2OBvYYhqFdu3Y5bDd7wPH777/rs88+c7n/jh07tHDhQo0fP74WRwUAAIDGjEtUHOByFdRnLVu2dNi2detWFRYW1uFoYE9aWprS09MdtoeHh9fhaNyrsLBQr7zySpUfN336dCUlJdXCiAAAAAACDqcIOVBfdezYUSEhIXbbsrKytG3btjoeEcpztuZEly5dnM7Cqe8+++wzh1vDxsbGauzYsXbbCgsL9dprr7FoLQAAAGoFAUclCDlQH/n4+Oiiiy5y2P7JJ5/U4Whgz48//uiwrXfv3nU4EvdKTEzUzJkzHbZPmjRJ9957r4KDg+22L1u2TMuWLaut4QEAAKARI+BwASEH3MnLy8thW1W2DnUWcCxfvlyrVq2q0rhKffrpp/roo4+q9diGaufOnU53RClv165dWrFihcP2QYMGuWNYlXLXe62UYRh6/fXXHV4CdeWVVyouLk4hISGaMGGCwzqvvPKK0wVYy3P38wAAAEDDRMDhIkIOuIuzXSSOHz/ucp0LL7xQ5557rsP2Z555Rvv27XO5nmEYWrhwoZ5//nlNmzZN77zzDpcS/K8DBw7orbfecun1KCws1EsvveSwPSQkRH379nXpvH/++ae+/vprffnll9q4caOKi4tdHrPkvvdaqSVLlmj58uV223x9fa0LNEvSNddco9jYWLt9U1JSNHfuXJfP6+7nAQAAgIaJgKMKCDngDoGBgQ7bli5d6vIv2z4+Prr99tsdtmdkZOjWW2/V6tWrK/1ifuzYMT3++OOaOnWq9diMGTM0Y8YMfiH/Xx9//LH+/e9/Kz8/32Gf3NxcTZ06VX/88YfDPjfccIP8/PycnquoqEhPP/20brjhBj311FN69tlndeutt+q2227TX3/95fKY3fVek86s7eJsYdF7771XUVFR1vu+vr6aNGmSw/7z5s3T9u3bXTq3O58HAAAAGi62ia0itpBFTbVp08Zh29GjRzVu3DiNGTNGkZGR8vLyUkZGhrp166bo6OgK/UeOHKmVK1fqhx9+sFsvMzNT9913nwYMGKBLL71UXbt2tS5umZmZqdTUVC1btkw///yz3dkB7777rgIDA3XbbbdV89k2LAsWLNDatWt14403qnfv3goJCZGPj49OnDihLVu2aMGCBUpMTHT4+ODgYP3jH/+o9DwLFy7UV199VeH4pk2b9Pzzz2v69Okujded77V33nlHR48etVsrMjJSN910U4XjcXFxuuqqq/Tdd9/ZfdzLL7+sefPmydfXt86eBwAAABouAo5qIORATXTo0EHNmzdXTk6O3fYDBw7o+eeftzn29ttv2/2y1qRJEz311FPavXu3Dh486PCc69at07p166o81vDwcI0cObLKj2vIjhw5otdff71aj33wwQcd7n5Tlr1wo9SyZct09OhRl7aZddd7bdu2bfrwww8dnmfixIkKCAiw23b//fdr6dKldtft2LJlixYtWuRw1xV3Pw8AAAA0bFyiUk2uXK4yfvx4p9PZ0Tj5+vpW+oWuKs4++2y99tprat26tdtqSlJERITefvttRUREuLVuY3XRRRfpuuuuc6nvoUOHnLZnZWW5VMcd77WioiKna4oMGDBAw4cPd9geGRmpe+65x2H7m2++qZSUFKdjcPdnBgAAAA0TAUcNVBZyjBo1Sv7+/nU4IpjF6NGjXfoF3lUxMTGaO3euw0Udq6pPnz6aP38+v4D/r8GDB+vSSy+t9uPPP/98Pf/88zrrrLNc6t+tWzen7aGhoS6fu6bvtS+++ELbtm1z2D5x4kQ1adLEaY2xY8cqMjLSblteXp6mT59e6Tox7v7MAAAAoOEh4KghRyHHxIkTdccdd3hgRDCDsLAwvfnmm279wtah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Bodjv+2226z91q5da+Tn5xtPPPGE03qBgYHG7NmzjZKSEpdf/zVr1hi9evVyeczBwcHGggULXK5f1syZM21qxcbGVqtOZUpKSowLL7zQep5Zs2a5tf6UKVOstUePHl2lx+7cudN44IEHDIvF4tLrbbFYjJdfftn4+++/ndbdvn27zeOOHDlirFy50oiOjnZaf8SIEcbBgwer/Bp88803Rp8+fVx+34SGhhp5eXlVPo+7nTp1ypg+fbrN353K/nP133jhwoWVvt6SjKFDhxqbN292Wuvdd9+19k9MTDS++eYbu7XefPNNwzDOvK/CwsIqtEdFRRmHDx+u8esGAAAAmJXHZnAYhqGxY8dq5cqV1mNdunRRSEiIEhMTdeTIEevxlStX6vrrr9fy5csVFBRkt9748eN15ZVX2hz77LPPtHXrVklS//79dc011zgdk6NfWvv376+XXnrJ5tj69ev13//+V5IUFBSkJ5980mnt1q1bO20vtW/fPn388cd6++23JZ1Z8yEmJkYWi0X79u1TRkaGJCk3N1f33XefsrOz9cQTT1Rad9WqVRoxYoROnz5tPebv76+uXbvK399fmZmZ2r17t017Zmamunbt6tK47T2Psnbs2KHc3NxqzwhxZN26dfrll18knfl3uPHGG91WOysrS2+99Zb1/j333FOlxx8+fFgzZ86scLxTp04KDw/XyZMntWPHDutrXlhYqMcee0yGYeixxx5z+TybNm3S6NGjVVhYKElq27at2rVrpxMnTujPP/+09luyZImuuOIK/fjjj2rXrl2ldYuLi/XMM8/oxRdfdHks0pkZSc2aNavSY9zt+PHjuv322/Xtt99W6XE33XST03bDMPTcc8/p2WeftTkeEhKi6OhonTp1SgcOHLCuB7NixQoNGTJEn3/+uS677LJKz79582ZNmDBBgYGB6tatm3bu3Gmt9eijj+raa6/VPffco7S0NHXo0EFBQUHWv3FJSUl644039MYbb1TpOQMAAAANRl2mKWV/SS39BTI8PNyYO3eukZ6ebu1XUlJibNu2zbjqqqtsfqF89dVXq3S+srND7rvvPrc+l//85z/W2hERETWqVXYGR2hoqCHJ6Nmzp7F48WKbX8JPnTplLFmyxOjZs6fN67J69Wqn9U+fPm3ExsZa+1944YXGunXrKsxYKSgoMHbs2GHMmzfPuPrq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n8/27dtHzO7q6moeeuih5uGHH27uu+++pr29vamq5ptvvrnsnNWrVw8dv3nz5ubRRx8d+r6tra259957m/nz5zcdHR0j1tuyZcsVz3Pjxo0jjpsyZUqzcOHCpre3t+nu7m66urpGPGbFihXNH3/8MerXpWmaZt26dSPm/fzzz2Oa9cEHH1z0+v7yyy9jmnMpp0+fblpbW4fmHzly5JrM/frrr5ubb775ouff3t7eLFiwoFm+fHkzb9685rrrrhv63cqVK5uDBw8Off/YY49ddvbRo0eHHjdx4sRm/fr1F60zefLkZsGCBc1dd9014v/gjjvuaL799tureg6//fZbs3bt2hEzLnwNP//hXwsXLhz167Vp06YRc9ra2sb8/jt58mQzf/78UZ/75s2brzj7rbfeGnHchAkTmnnz5jWzZs0a+psfvtbOnTsvO+/NN9/8y/UHBwcvmncpw//G/2otAAD4NxvbbSKCvP7663X+/PnauXPn0M+OHTtWx44d+9uzV69eXT/88ENt3Lhx6GenTp36W/sV/P777/XOO+9UR0dHbd26tc6dO1eHDh0a8bgbbrihtmzZUmvWrLnizOG3zrzg+PHjl/w0S1VVW1tbPffcc7V+/fox30nkfzewnDFjxpj3tejr6xv697p162r8+PFjmnMpO3bsGLp8YfHixXX33Xdfk7lTpkyp3bt316pVq+rEiRNVVTUwMHDJT/ls2LChXnzxxWqaptra2urcuXNXvU5vb2+9/PLLNXHixHr++edrcHCwTpw4MbTmcD09PbVt27arvqVwa2trbd26tebMmVMvvfTSiPfL5T6V1NraetXnf8HwzUEvWLZs2Zjff11dXfXhhx/Wq6++Wq+99lqdPXv2ot9f7tyvv/76K85+8skna/LkyfXss8/WZ599VlX/vUzo+++/H/HY2bNn1yuvvHLVG80CAABj968PHDfddFPt2LGjnnrqqXrvvffqwIED1d/fX3/++Wd1dHRUZ2dn3XnnnWO6C0lLS0tt2LChent7a9euXbV///768ssv6+zZszVhwoTq6Oio6dOn1/Tp04duvXolAwMDdeONN1ZfX1+tWrWq3n333dq/f38dP368xo0bV1OnTq2enp5atmzZiH1ALufpp5+uJUuW1P79++vw4cP11VdfVX9/fw0MDNTg4GDdcsst1dnZWTNnzqw5c+bUokWLLhlFRmPlypV19OjRev/99+u2226rLVu2jGnOkSNHhvYEaW1trRUrVvyt8xru119/vejSl+GbSF4L8+bNq0OHDtWuXbtq79699emnn9ZPP/1UXV1dNWnSpHrggQdq8eLFF93adOHChVe1yewF8+fPr5aWlnrmmWfqkUceqd27d9e+ffvqiy++qDNnztTkyZPr/vvvr6VLl1ZPT8+og0FLS0utWrWqli9fXh999FEdOHCgDh48WKdOnaqTJ0/W+PHj69Zbb61p06bVzJkza/bs2TV37txRrVH130ti+vr6avv27XXmzJlatGhRbdq0adRzhhs/fny98MILtXbt2tq3b1998skn9fnnn9fp06fru+++q/b29po4cWJNmzat7rnnnpo7d+5VB64HH3ywDhw4UHv37q09e/bU4cOHq7+/v8aNG1eTJk2qWbNmVXd3d3V3d4850gAAAKPT0jRjvEUG18wTTzwxtA/EmjVratu2bf/wGQEAAECWf/Umo4n0JgAAABg9gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4rU0TdP80ycBAAAA8Hf4BAcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEE/gAAAAAOIJHAAAAEA8gQMAAACIJ3AAAAAA8QQOAAAAIJ7AAQAAAMQTOAAAAIB4AgcAAAAQT+AAAAAA4gkcAAAAQDyBAwAAAIgncAAAAADxBA4AAAAgnsABAAAAxBM4AAAAgHgCBwAAABBP4AAAAADiCRwAAABAPIEDAAAAiCdwAAAAAPEEDgAAACCewAEAAADEEzgAAACAeAIHAAAAEO8/GYttnS/9PnYAAAAASUVORK5CYII=)




