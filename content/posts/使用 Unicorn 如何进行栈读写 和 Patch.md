+++
title = '使用 Unicorn 如何进行栈读写 和 Patch'
date = 2025-02-23T17:56:08.538560+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# **struct.pack 方法介绍**



struct.pack 是 Python 标准库 struct 模块中的一个函数，它用于将 Python 的基本数据类型（如 int、float、long）打包为字节流，以便在二进制文件、网络传输或内存操作（如 Unicorn 仿真器的 mem_write）中使用。



语法：

```
import struct

struct.pack(format, value)
```
- format：指定数据的格式，例如：

- <f：表示小端（<）的 4 字节浮点数（float）

- <d：表示小端的 8 字节双精度浮点数（double）

- value：要转换的 Python 值。



**数据类型格式**

| 数据类型 | 有符号格式（小写） | 无符号格式（大写） | 大小（字节） |
|--- | --- | --- | ---|
| byte | b (char) | B (uchar) | 1 |
| short | h (short) | H (ushort) | 2 |
| int | i (int) | I (uint) | 4 |
| long | q (long long) | Q (ulong long) | 8 |
| float | f (float) | 无 | 4 |
| double | d (double) | 无 | 8 |


**其他特殊类型**

| 格式 | 说明 | 字节数 |
|--- | --- | ---|
| x | 跳过的填充字节 | 1 |
| s | char[]（字符串） | 可变 |
| p | Pascal 风格字符串（首字节存长度） | 可变 |
| ? | bool（布尔值） | 1 |


**字节顺序（大小端）**

| 前缀 | 说明 |
|--- | ---|
| @ | 按本机字节顺序存储 |
| < | 小端（Little-Endian） |
| > | 大端（Big-Endian） |
| = | 按本机字节序存储（无对齐） |
| ! | 网络字节序（大端，等价于 > ） |


# **Unicorn 中栈读写示例**



使用 Unicorn 模拟器进行栈操作，并使用 struct 处理数据打包/解包。

```
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import *
import struct

# 定义内存布局
STACK_ADDR = 0x400000  # 栈基址
STACK_SIZE = 0x10000   # 栈大小

# 初始化 Unicorn
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 分配栈空间
mu.mem_map(STACK_ADDR, STACK_SIZE)

# 设置 SP（栈指针）
sp_init = STACK_ADDR + STACK_SIZE - 0x10  # 预留一点空间
mu.reg_write(UC_ARM64_REG_SP, sp_init)

# 直接写入各种数据类型到栈
sp = mu.reg_read(UC_ARM64_REG_SP)

# 写入 byte
byte_value = 0x12
sp -= 1
mu.mem_write(sp, struct.pack('<B', byte_value))
print(f"Pushed byte {hex(byte_value)} to stack at {hex(sp)}")

# 写入 short
short_value = 0x1234
sp -= 2
mu.mem_write(sp, struct.pack('<H', short_value))
print(f"Pushed short {hex(short_value)} to stack at {hex(sp)}")

# 写入 int
int_value = 0x12345678
sp -= 4
mu.mem_write(sp, struct.pack('<I', int_value))
print(f"Pushed int {hex(int_value)} to stack at {hex(sp)}")

# 写入 long
long_value = 0x12345678ABCDEF01
sp -= 8
mu.mem_write(sp, struct.pack('<Q', long_value))
print(f"Pushed long {hex(long_value)} to stack at {hex(sp)}")

# 写入 float
float_value = 3.14
sp -= 4
mu.mem_write(sp, struct.pack('<f', float_value))
print(f"Pushed float {float_value} to stack at {hex(sp)}")

# 写入 double
double_value = 2.718281828459
sp -= 8
mu.mem_write(sp, struct.pack('<d', double_value))
print(f"Pushed double {double_value} to stack at {hex(sp)}")

mu.reg_write(UC_ARM64_REG_SP, sp)

# 直接从栈读取数据
# 读取 double
double_read = struct.unpack('<d', mu.mem_read(sp, 8))[0]
print(f"Popped double {double_read} from stack at {hex(sp)}")
sp += 8

# 读取 float
float_read = struct.unpack('<f', mu.mem_read(sp, 4))[0]
print(f"Popped float {float_read} from stack at {hex(sp)}")
sp += 4

# 读取 long
long_read = struct.unpack('<Q', mu.mem_read(sp, 8))[0]
print(f"Popped long {hex(long_read)} from stack at {hex(sp)}")
sp += 8

# 读取 int
int_read = struct.unpack('<I', mu.mem_read(sp, 4))[0]
print(f"Popped int {hex(int_read)} from stack at {hex(sp)}")
sp += 4

# 读取 short
short_read = struct.unpack('<H', mu.mem_read(sp, 2))[0]
print(f"Popped short {hex(short_read)} from stack at {hex(sp)}")
sp += 2

# 读取 byte
byte_read = struct.unpack('<B', mu.mem_read(sp, 1))[0]
print(f"Popped byte {hex(byte_read)} from stack at {hex(sp)}")
sp += 1

mu.reg_write(UC_ARM64_REG_SP, sp)
print("Stack read/write successful for all data types!")
```


输出如下：

```
Pushed byte 0x12 to stack at 0x40ffef
Pushed short 0x1234 to stack at 0x40ffed
Pushed int 0x12345678 to stack at 0x40ffe9
Pushed long 0x12345678abcdef01 to stack at 0x40ffe1
Pushed float 3.14 to stack at 0x40ffdd
Pushed double 2.718281828459 to stack at 0x40ffd5
Popped double 2.718281828459 from stack at 0x40ffd5
Popped float 3.140000104904175 from stack at 0x40ffdd
Popped long 0x12345678abcdef01 from stack at 0x40ffe1
Popped int 0x12345678 from stack at 0x40ffe9
Popped short 0x1234 from stack at 0x40ffed
Popped byte 0x12 from stack at 0x40ffef
Stack read/write successful for all data types!
```


# **Unicorn 中 Patch 示例**



在 Unicorn 中，可以通过 mem_write 方法直接修改指定地址的指令数据。例如，要将某个位置的指令替换为 NOP。



在 ARM64 架构下，NOP 指令的机器码是：

```
NOP = 0xD503201F  # (ARM64 指令，大端)
```
它占用 4 字节。



假设你要将 0x1000 处的指令替换为 NOP：

```
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM

# 初始化 Unicorn
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 分配内存（假设代码段在 0x1000 处）
CODE_ADDR = 0x1000
CODE_SIZE = 0x1000
mu.mem_map(CODE_ADDR, CODE_SIZE)

# 写入示例代码（假设已有一些指令）
original_code = b"\x00\x00\xA0\xE3"  # 伪造一条指令（MOV R0, #0）
mu.mem_write(CODE_ADDR, original_code)

# 替换为 NOP 指令
nop_opcode = struct.pack("<I", 0xD503201F)  # ARM64 NOP 指令（小端存储）
mu.mem_write(CODE_ADDR, nop_opcode)

# 读取并验证
patched_code = mu.mem_read(CODE_ADDR, 4)
print(f"Patched instruction: {patched_code.hex()}")  # 应输出 "1f2003d5"
```


输出如下：

```
Patched instruction: 1f2003d5
```
从输出可以看到已经成功将指定地址的指令 Patch 为 NOP 了。











