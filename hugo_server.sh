#!/bin/bash
hugo
git add .
git commit -m "使用 Frida 定位 JNI 方法内存地址"
git push
