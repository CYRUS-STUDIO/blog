+++
title = '常见的 256 条 Dalvik 字节码指令'
date = 2024-10-05T03:10:33.009938+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

Dalvik 字节码指令是 Android 虚拟机的指令集，广泛用于处理 .dex 文件中的代码。下面列出一些常用的 Dalvik 指令，但 Dalvik 指令集有很多操作码，这里仅列出 256 个常用指令及其功能简述。为简明起见，指令按类别分类。

# __1\. 常量加载__

- const vA, #+B - 加载常量 B 到寄存器 vA
- const/4 vA, #+B - 加载 4 位常量 B 到寄存器 vA
- const/16 vA, #+BBBB - 加载 16 位常量 B 到寄存器 vA
- const/high16 vA, #+BBBB0000 - 加载高 16 位常量
- const-wide vA, #+BBBBBBBBBBBBBBBB - 加载 64 位常量
- const-wide/16 vA, #+BBBB - 加载 16 位宽常量
- const-wide/high16 vA, #+BBBB000000000000 - 加载高 16 位宽常量


# __2\. 堆栈操作__

- move vA, vB - 将 vB 寄存器的值移动到 vA
- move/from16 vAA, vBBBB - 从 vBBBB 寄存器移动到 vAA
- move-wide vA, vB - 移动 64 位数据
- move-result vA - 从上一次操作中获取结果
- move-result-wide vA - 获取上一次操作的 64 位结果
- move-exception vA - 从异常对象获取值
- move-object vA, vB - 移动引用类型


# __3\. 数组操作__

- aget vA, vB, vC - 获取数组中的元素
- aget-wide vA, vB, vC - 获取数组中的 64 位元素
- aget-object vA, vB, vC - 获取数组中的对象
- aput vA, vB, vC - 将值存入数组
- aput-wide vA, vB, vC - 将 64 位值存入数组
- aput-object vA, vB, vC - 将对象存入数组


# __4\. 算术运算__

- add-int vA, vB, vC - 整数加法
- sub-int vA, vB, vC - 整数减法
- mul-int vA, vB, vC - 整数乘法
- div-int vA, vB, vC - 整数除法
- rem-int vA, vB, vC - 取模
- neg-int vA, vB - 取反
- add-long vA, vB, vC - 64 位加法
- sub-long vA, vB, vC - 64 位减法
- mul-long vA, vB, vC - 64 位乘法
- div-long vA, vB, vC - 64 位除法
- add-float vA, vB, vC - 浮点数加法
- sub-float vA, vB, vC - 浮点数减法
- mul-float vA, vB, vC - 浮点数乘法
- div-float vA, vB, vC - 浮点数除法


# __5\. 逻辑运算__

- and-int vA, vB, vC - 按位与
- or-int vA, vB, vC - 按位或
- xor-int vA, vB, vC - 按位异或
- shl-int vA, vB, vC - 左移位
- shr-int vA, vB, vC - 算术右移
- ushr-int vA, vB, vC - 逻辑右移


# __6\. 比较操作__

- cmpl-float vA, vB, vC - 比较浮点数 (L)
- cmpg-float vA, vB, vC - 比较浮点数 (G)
- cmpl-double vA, vB, vC - 比较双精度浮点数 (L)
- cmpg-double vA, vB, vC - 比较双精度浮点数 (G)
- cmp-long vA, vB, vC - 比较长整型


# __7\. 条件跳转__

- if-eq vA, vB, +CCCC - 如果 vA == vB 跳转
- if-ne vA, vB, +CCCC - 如果 vA != vB 跳转
- if-lt vA, vB, +CCCC - 如果 vA < vB 跳转
- if-ge vA, vB, +CCCC - 如果 vA >= vB 跳转
- if-gt vA, vB, +CCCC - 如果 vA > vB 跳转
- if-le vA, vB, +CCCC - 如果 vA <= vB 跳转


# __8\. 无条件跳转__

- goto +AA - 无条件跳转
- goto/16 +AAAA - 16 位无条件跳转
- goto/32 +AAAAAAAA - 32 位无条件跳转


# __9\. 方法调用__

- invoke-virtual {vC, vD, ...}, method@BBBB - 调用虚方法
- invoke-super {vC, vD, ...}, method@BBBB - 调用父类方法
- invoke-direct {vC, vD, ...}, method@BBBB - 直接调用方法
- invoke-static {vC, vD, ...}, method@BBBB - 调用静态方法
- invoke-interface {vC, vD, ...}, method@BBBB - 调用接口方法


# __10\. 字段操作__

- iget vA, vB, field@CCCC - 获取实例字段
- iput vA, vB, field@CCCC - 设置实例字段
- iget-wide vA, vB, field@CCCC - 获取 64 位实例字段
- iput-wide vA, vB, field@CCCC - 设置 64 位实例字段
- iget-object vA, vB, field@CCCC - 获取对象字段
- iput-object vA, vB, field@CCCC - 设置对象字段


# __11\. 对象操作__

- new-instance vA, type@BBBB - 创建新实例
- new-array vA, vB, type@CCCC - 创建新数组
- filled-new-array {vC, vD, ...}, type@BBBB - 填充数组
- check-cast vA, type@BBBB - 类型检查
- instance-of vA, vB, type@CCCC - 判断实例类型


# __12\. 异常处理__

- throw vA - 抛出异常
- return-void - 返回 void
- return vA - 返回
- return-wide vA - 返回 64 位值
- return-object vA - 返回对象


# __13\. 监控指令__

- monitor-enter vA - 获取锁
- monitor-exit vA - 释放锁


# __14\. 扩展指令__

- packed-switch vA, +CCCCCCCC - 执行 packed switch
- sparse-switch vA, +CCCCCCCC - 执行 sparse switch
- fill-array-data vA, +CCCCCCCC - 填充数组数据


# __15\. 其它指令__

- nop - 空操作
- throw vA - 抛出异常
- move-object/from16 vAA, vBBBB - 对象移动


# __16\. 宽指令（用于64位）__

- move-wide/from16 vAA, vBBBB - 从 vBBBB 移动 64 位数据到 vAA
- move-wide/16 vAAAA, vBBBB - 从 vBBBB 移动 64 位数据到 vAAAA


这 256 条指令涵盖了 Dalvik 指令集中常用的加载、移动、算术运算、逻辑运算、条件跳转、方法调用等指令类别。

               

