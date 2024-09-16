+++
title = '解决LineageOS提示网络受限问题'
date = 2024-09-16T21:34:05.666467+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# __问题原因__


由于 LineageOS 源码里默认是使用 google captive连接验证服务，所以国内会一直提示网络受限，但是实际上是可以访问网络的。

要解决这个问题可以通过把 captive_portal_https_url 改为国内的就好了，比如用MIUI的。

# __更换 captive 连接验证服务器__


## __1\. 通过 adb 修改__


```
adb shell settings put global captive_portal_https_url https://connect.rom.miui.com/generate_204

adb shell settings put global captive_portal_http_url http://connect.rom.miui.com/generate_204
```

## __2\. 修改源码__


编辑 packages/modules/NetworkStack/res/values/config.xml
```
<!-- HTTP URL for network validation, to use for detecting captive portals. -->
<string name="default_captive_portal_http_url" translatable="false">http://connectivitycheck.gstatic.com/generate_204</string>

<!-- HTTPS URL for network validation, to use for confirming internet connectivity. -->
<string name="default_captive_portal_https_url" translatable="false">https://www.google.com/generate_204</string>

<!-- List of fallback URLs to use for detecting captive portals. -->
<string-array name="default_captive_portal_fallback_urls" translatable="false">
    <item>http://www.google.com/gen_204</item>
    <item>http://play.googleapis.com/generate_204</item>
</string-array>
```
修改如下
```
<!-- HTTP URL for network validation, to use for detecting captive portals. -->
<string name="default_captive_portal_http_url" translatable="false">https://connect.rom.miui.com/generate_204</string>

<!-- HTTPS URL for network validation, to use for confirming internet connectivity. -->
<string name="default_captive_portal_https_url" translatable="false">https://connect.rom.miui.com/generate_204</string>

<!-- List of fallback URLs to use for detecting captive portals. -->
<string-array name="default_captive_portal_fallback_urls" translatable="false">
    <item>https://connect.rom.miui.com/generate_204</item>
    <item>https://connect.rom.miui.com/generate_204</item>
</string-array>
```

# __当时间不准时修改使用（修改为阿里云）__


## __1\. 通过adb修改__


```
adb shell settings put global ntp_server ntp.aliyun.com
```

## __2\. 修改源码__


编辑 device/vendor/device/gps/etc/gps.conf（vendor和device是对应的厂家和设备）
```
#NTP server
NTP_SERVER=time.izatcloud.net
```
修改如下
```
#NTP server
NTP_SERVER=ntp.aliyun.com
```

参考：
[原生安卓-解决WiFi网络受限以及修改NTP服务器](https://www.jeeinn.com/2024/03/2336/comment-page-1/)


               

