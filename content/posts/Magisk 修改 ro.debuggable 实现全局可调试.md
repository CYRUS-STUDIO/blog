+++
title = 'Magisk 修改 ro.debuggable 实现全局可调试'
date = 2025-07-25T03:28:28.277272+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# ro.debuggable



通过修改 android 系统 中的 ro.debuggable 属性，开启系统调试通道，使设备上所有 app 可调试。



ro.debuggable 一般在系统的 build.prop 或构建配置文件中设置，比如：

```
ro.debuggable=1
```


在编译 AOSP 时，这个值通常在 build/core/main.mk 中由 user, userdebug, eng 等 build 类型决定：

| build 类型 | ro.debuggable |
|--- | ---|
| user | 0 |
| userdebug | 1 |
| eng | 1 |


# 如何查看当前设备的 ro.debuggable



通过 adb 命令查看：

```
adb shell getprop ro.debuggable
```
输出：

- 0：系统为非调试版本（普通用户设备）

- 1：系统为调试版本（如 LineageOS 的 userdebug 或 eng 版本）



# MagiskHidePropsConf



MagiskHidePropsConf 是一个基于 Magisk 模块系统的工具模块，主要功能是：修改 Android 设备的系统属性（System Properties）以“伪装”或“欺骗”应用和检测机制。



下载 MagiskHidePropsConf：[https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf/tags](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf/tags)



把下载下来的 MagiskHidePropsConf 推送到手机 sdcard 上

```
adb push "D:\app逆向\MagiskHidePropsConf-v6.1.2.zi
p" /sdcard/
```


安装 MagiskHidePropsConf，打开 Magick【模块】【本地安装】【选择MagiskHidePropsConf-v6.1.2.zi
p】



重启手机，进入 adb shell



输入props

```
meri:/ # props

Loading... Please wait.


MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 Updating fingerprints list
=====================================


Checking list version.
! File not downloaded!

Checking for module update.
! File not downloaded!

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 Select an option below.
=====================================

1 - Edit device fingerprint
2 - Force BASIC key attestation
3 - Device simulation (disabled)
4 - Edit MagiskHide props (active)
5 - Add/edit custom props
6 - Delete prop values
7 - Script settings
8 - Collect logs
u - Perform module update check
r - Reset all options/settings
b - Reboot device
e - Exit

See the module readme or the
support thread @ XDA for details.
```


输入 5 - Add/edit custom props


```
Enter your desired option: 5

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 Custom props
 Select an option below:
=====================================

Set or edit custom prop values for your device.

Currently no custom props set.
Please add one by selecting
"New custom prop" below.

n - New custom prop
b - Go back to main menu
e - Exit

See the module readme or the
support thread @ XDA for details.
```


输入n

```
Enter your desired option: n

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 New custom prop
=====================================

Enter the prop to set. Example:
ro.sf.lcd_density

b - Go back
e - Exit
```


输入 ro.debuggable

```
Enter your desired option: ro.debuggable

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 ro.debuggable
=====================================

ro.debuggable is
one of the sensitive props that can be
set by the MagiskHide props option.

Are you sure you want to proceed?

y - Yes
n - No
e - Exit
```


输入y

```
Enter your desired option: y

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 ro.debuggable
=====================================

Enter the value you want to set
ro.debuggable to,
or select from the options below.

The currently set value is:
0
Please enter the new value.

b - Go back
e - Exit
```


输入1

```
Enter your desired option: 1

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 ro.debuggable
=====================================

This will set ro.debuggable to:

1

Pick an option below to change
what boot stage the prop will
be set in, or set/reset a delay:

1 - Default (current)
2 - post-fs-data
3 - late_start service
4 - Both boot stages
d - Delay
```


输入y，设置完成后重启手机

```
Do you want to continue?

Enter y(es), n(o), e(xit)
or an option from above: y

Working. Please wait...

Working. Please wait...

Working. Please wait...

Working. Please wait...

Working. Please wait...

MagiskHide Props Config v6.1.2
by Didgeridoohan @ XDA Developers

=====================================
 Reboot - ro.debuggable
=====================================

Reboot for changes to take effect.

Do you want to reboot now (y/n)?

Enter y(es), n(o) or e(xit): y

Rebooting...
```


重置完成后，进入adb shell 执行 getprop ro.debuggable 检查值是否为1





