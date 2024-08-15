+++
title = '修改android系统ro.debuggable使全局可调试'
date = 2024-08-16T00:04:11.953663+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

修改 android 系统 中的 ro.debuggable 属性使设备上所有 app 可调试。

下载MagiskHidePropsConf：[https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf/tags](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf/tags)

把下载下来的MagiskHidePropsConf推送到手机sdcard上
```
adb push "D:\app逆向\MagiskHidePropsConf-v6.1.2.zip" /sdcard/
```

安装MagiskHidePropsConf，打开Magick【模块】【本地安装】【选择MagiskHidePropsConf-v6.1.2.zi
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

参考：
1. [Android修改ro.debuggable 的四种方法](https://blog.csdn.net/jinmie0193/article/details/111355867)
2. [Android搞机之打开系统调试总开关ro.debuggable](https://segmentfault.com/a/1190000044292145)


               
               

