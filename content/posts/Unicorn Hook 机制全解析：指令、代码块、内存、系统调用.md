+++
title = 'Unicorn Hook 机制全解析：指令、代码块、内存、系统调用'
date = 2025-07-11T00:41:47.246013+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# Hook 主要类型



在 Unicorn 中，Hook（钩子）用于在模拟过程中拦截 CPU 指令执行、内存访问等操作，以便分析和修改执行行为。



Unicorn 提供了多种 Hook 类型，每种类型用于不同场景：

| Hook 类型 | 说明 | 示例 |
|--- | --- | ---|
| UC_HOOK_CODE | 拦截每一条指令执行 | 监控指令流，反调试 |
| UC_HOOK_BLOCK | 拦截每个基本块执行 | 统计基本块执行次数 |
| UC_HOOK_INTR | 拦截中断指令（如 svc #0） | 监控系统调用 |
| UC_HOOK_MEM_READ | 读取内存前触发 | 监视变量读取 |
| UC_HOOK_MEM_WRITE | 写入内存前触发 | 监视变量修改 |
| UC_HOOK_MEM_FETCH | 取指令前触发 | 捕获未映射代码执行 |
| UC_HOOK_MEM_READ_UNMAPPED | 读取未映射内存 | 捕获非法内存读取 |
| UC_HOOK_MEM_WRITE_UNMAPPED | 写入未映射内存 | 捕获非法内存写入 |
| UC_HOOK_MEM_FETCH_UNMAPPED | 取指未映射内存 | 捕获非法指令执行 |
| UC_HOOK_INSN | 拦截特定指令 | 监控 syscall、hlt 等 |


# Hook 指令执行 (UC_HOOK_CODE)



**用途** ：

- 监控所有执行的指令

- 记录寄存器变化

- 反调试



示例代码

```
from unicorn import *
from unicorn.arm64_const import *

# Hook 回调函数
def hook_code(mu, address, size, user_data):
    print(f"Executing instruction at 0x{address:X}, size={size}")

# 初始化 Unicorn ARM64
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 分配内存
BASE = 0x1000
mu.mem_map(BASE, 0x1000)

# 写入简单的 ARM64 指令
code = b"\x20\x00\x80\xd2"  # MOV X0, #1
mu.mem_write(BASE, code)

# 注册 Hook
mu.hook_add(UC_HOOK_CODE, hook_code)

# 设置 PC 并执行
mu.reg_write(UC_ARM64_REG_PC, BASE)
mu.emu_start(BASE, BASE + len(code))
```


输出如下：

```
Executing instruction at 0x1000, size=4
```


# Hook 代码块（UC_HOOK_BLOCK ）



UC_HOOK_BLOCK用于 Hook 代码块（Basic Block）执行，在 Unicorn 模拟执行时，每进入一个新的 Basic Block，都会触发 Hook 回调。



示例代码

1. 模拟执行 ARM64 代码

1. 使用 UC_HOOK_BLOCK 监听代码块执行

1. 打印每个 Block 的起始地址

```
from unicorn import *
from unicorn.arm64_const import *

# **ARM64 指令**
# 代码块0x1000
CODE  = b"\x20\x00\x80\x52"  # MOV W0, #1
CODE += b"\x21\x00\x80\x52"  # MOV W1, #1
CODE += b"\x00\x00\x00\xB4"  # CBZ W0, label
# 代码块0x100C
CODE += b"\x42\x00\x80\x52"  # MOV W2, #2
CODE += b"\xC0\x03\x5F\xD6"  # RET

# **HOOK 代码块**
def hook_block(mu, address, size, user_data):
    print(f"[HOOK] 进入代码块: 0x{address:X} (大小: {size} 字节)")

# **HOOK 访问未映射内存**
def hook_unmapped(mu, access, address, size, value, user_data):
    print(f"[HOOK] 访问未映射内存: 0x{address:X}")
    return False  # 终止执行，避免崩溃

# **初始化 Unicorn**
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# **映射内存**
CODE_BASE = 0x1000
mu.mem_map(CODE_BASE, 0x1000)
mu.mem_write(CODE_BASE, CODE)

# **设置寄存器**
mu.reg_write(UC_ARM64_REG_PC, CODE_BASE)

# **添加 Hook**
mu.hook_add(UC_HOOK_BLOCK, hook_block)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped)

# **执行代码**
try:
    print("[INFO] 开始执行代码...")
    mu.emu_start(CODE_BASE, CODE_BASE + len(CODE) - 4)  # 因为 RET 是最后一条指令，不应执行超出范围的地址，所有 -4
    print("[INFO] 执行完成")
except UcError as e:
    print(f"[ERROR] Unicorn 运行错误: {e}")
```


输出如下：

```
[INFO] 开始执行代码...
[HOOK] 进入代码块: 0x1000 (大小: 12 字节)
[HOOK] 进入代码块: 0x100C (大小: 4 字节)
[INFO] 执行完成
```


# Hook 内存读写 (UC_HOOK_MEM_READ & UC_HOOK_MEM_WRITE)



**用途** ：

- 监视特定变量

- 反调试检测



```
from unicorn import *
from unicorn.arm64_const import *

# 内存区域
MEMORY_BASE = 0x1000
MEMORY_SIZE = 0x1000

# 目标内存地址
TARGET_ADDR = MEMORY_BASE + 0x200  # 目标变量存储地址

# 需要执行的 ARM64 代码：
# MOV W0, #42    ->  40 05 80 52  (把 42 存入 W0)
# STR W0, [X1]   ->  20 00 00 B9  (把 W0 的值存入 X1 指向的地址)
# LDR W2, [X1]   ->  22 00 40 B9  (从 X1 指向的地址加载值到 W2)
# BR X30         ->  C0 03 5F D6  (返回)

CODE = b"\x40\x05\x80\x52"  # MOV W0, #42
CODE += b"\x20\x00\x00\xB9"  # STR W0, [X1]
CODE += b"\x22\x00\x40\xB9"  # LDR W2, [X1]
CODE += b"\xC0\x03\x5F\xD6"  # BR X30 (Return)

# 监控内存读取
def hook_mem_read(mu, access, address, size, value, user_data):
    print(f"[MEM_READ] Address: 0x{address:X}, Size: {size}")

# 监控内存写入
def hook_mem_write(mu, access, address, size, value, user_data):
    print(f"[MEM_WRITE] Address: 0x{address:X}, Size: {size}, Value: 0x{value:X}")

# 初始化 Unicorn ARM64
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 分配内存
mu.mem_map(MEMORY_BASE, MEMORY_SIZE)

# 写入代码到内存
mu.mem_write(MEMORY_BASE, CODE)

# 分配数据内存并初始化
mu.mem_write(TARGET_ADDR, b"\x00\x00\x00\x00")  # 目标地址初始化为 0

# 注册 Hook
mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)

# 设置寄存器
mu.reg_write(UC_ARM64_REG_X1, TARGET_ADDR)  # X1 指向目标内存
mu.reg_write(UC_ARM64_REG_X30, MEMORY_BASE + len(CODE))  # 设置返回地址

# 启动仿真
mu.emu_start(MEMORY_BASE, MEMORY_BASE + len(CODE))

# 读取结果
result = mu.reg_read(UC_ARM64_REG_W2)
print(f"\n[RESULT] W2 = {result}")
```


输出如下：

```
[MEM_WRITE] Address: 0x1200, Size: 4, Value: 0x2A
[MEM_READ] Address: 0x1200, Size: 4

[RESULT] W2 = 42
```


默认情况下，UC_HOOK_MEM_READ 和 UC_HOOK_MEM_WRITE 会监听所有内存地址的读写。但是，你可以指定特定的内存范围来限制 Hook 的触发范围。



你可以传入 begin 和 end 地址参数，让 Hook 只作用于特定区域：

```
mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin=0x1000, end=0x2000)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=0x1000, end=0x2000)
```
只监听 0x1000 到 0x2000 之间的内存访问。



# Hook 未映射内存 (UC_HOOK_MEM_READ_UNMAPPED)



**用途** ：

- 捕获非法内存访问

- 监测程序崩溃



```
from unicorn import *
from unicorn.arm64_const import *

# **示例: 访问未映射内存**
UNMAPPED_ADDR = 0x2000  # 这里的地址没有 mem_map

# ARM64 代码: 读取 `UNMAPPED_ADDR`
CODE = b"\x22\x00\x40\xB9"  # LDR W2, [X1]
CODE += b"\xC0\x03\x5F\xD6"  # BR X30


# **Hook 处理函数**
def hook_mem_read_unmapped(mu, access, address, size, value, user_data):
    print(f"[HOOK] 未映射内存读取: Address=0x{address:X}, Size={size}")
    return False  # 返回 False 让 Unicorn 抛出异常 (或者返回 True 继续执行)


# 初始化 Unicorn
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 仅映射代码区, **不映射 UNMAPPED_ADDR**
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, CODE)

# Hook 未映射内存的读取
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)

# 设置寄存器
mu.reg_write(UC_ARM64_REG_X1, UNMAPPED_ADDR)  # X1 = 未映射地址
mu.reg_write(UC_ARM64_REG_X30, 0x1000 + len(CODE))  # 返回地址

# **运行 Unicorn**
try:
    mu.emu_start(0x1000, 0x1000 + len(CODE))
except UcError as e:
    print(f"[ERROR] Unicorn 运行错误: {e}")
```


输出如下：

```
[HOOK] 未映射内存读取: Address=0x2000, Size=4
[ERROR] Unicorn 运行错误: Invalid memory read (UC_ERR_READ_UNMAPPED)
```


# Hook 系统调用 (UC_HOOK_INTR)



**用途** ：

- 监视 svc #0 系统调用

- 处理 syscall



关于Android系统调用参考这篇文章：[深入 Android syscall 实现：内联汇编系统调用 + NDK 汇编构建](https://cyrus-studio.github.io/blog/posts/%E6%B7%B1%E5%85%A5-android-syscall-%E5%AE%9E%E7%8E%B0%E5%86%85%E8%81%94%E6%B1%87%E7%BC%96%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8-+-ndk-%E6%B1%87%E7%BC%96%E6%9E%84%E5%BB%BA/)



```
from unicorn import *
from unicorn.arm64_const import *

# **ARM64 SVC 代码**
CODE = b"\x01\x00\x00\xD4"  # SVC #0
CODE += b"\xC0\x03\x5F\xD6"  # BR X30 (返回)


# **Hook 处理函数**
def hook_syscall(mu, intno, user_data):
    syscall_num = mu.reg_read(UC_ARM64_REG_X8)  # 读取系统调用号 (X8)
    print(f"[HOOK] 捕获系统调用: X8 = {syscall_num}")

    if syscall_num == 1:  # 例如: 模拟 write(1, "Hello", 5)
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # 文件描述符
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # 缓冲区地址
        x2 = mu.reg_read(UC_ARM64_REG_X2)  # 字节数
        data = mu.mem_read(x1, x2).decode(errors="ignore")
        print(f"[模拟] write({x0}, \"{data}\", {x2})")
        mu.reg_write(UC_ARM64_REG_X0, x2)  # 返回写入的字节数
    else:
        print("[ERROR] 未知系统调用")
        mu.reg_write(UC_ARM64_REG_X0, -1)  # 返回错误


# **初始化 Unicorn**
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# **映射内存**
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, CODE)

# **设置 SVC 调用参数 (模拟 write)**
buf_addr = 0x2000
mu.mem_map(buf_addr, 0x1000)
mu.mem_write(buf_addr, b"Hello Unicorn!\x00")

mu.reg_write(UC_ARM64_REG_X8, 1)  # 系统调用号 (write)
mu.reg_write(UC_ARM64_REG_X0, 1)  # 文件描述符 (stdout)
mu.reg_write(UC_ARM64_REG_X1, buf_addr)  # 缓冲区地址
mu.reg_write(UC_ARM64_REG_X2, 14)  # 字节数
mu.reg_write(UC_ARM64_REG_X30, 0x1000 + len(CODE))  # 返回地址

# **Hook SVC 指令**
mu.hook_add(UC_HOOK_INTR, hook_syscall)

# **运行 Unicorn**
try:
    mu.emu_start(0x1000, 0x1000 + len(CODE))
except UcError as e:
    print(f"[ERROR] Unicorn 运行错误: {e}")
```


输出如下：

```
[HOOK] 捕获系统调用: X8 = 1
[模拟] write(1, "Hello Unicorn!", 14)
```


# Hook 的移除



如果不再需要 Hook，可以使用 mu.hook_del(hook_id) 取消 Hook：

```
hook_id = mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_del(hook_id)
```


下面是一个完整的示例代码，演示了如何 添加、触发 和 移除 Hook。

```
from unicorn import *
from unicorn.arm64_const import *

# **ARM64 测试代码**
CODE = b"\x01\x00\x00\xD4"  # SVC #0 (触发系统调用)
CODE += b"\xC0\x03\x5F\xD6"  # BR X30 (返回)


# **Hook 处理函数**
def hook_syscall(mu, intno, user_data):
    syscall_num = mu.reg_read(UC_ARM64_REG_X8)  # 读取系统调用号 (X8)
    print(f"[HOOK] 捕获系统调用: X8 = {syscall_num}")

    if syscall_num == 1:
        print("[模拟] 执行 write 系统调用")
        mu.reg_write(UC_ARM64_REG_X0, 42)  # 模拟返回值
    else:
        print("[ERROR] 未知系统调用")
        mu.reg_write(UC_ARM64_REG_X0, -1)  # 返回错误


# **初始化 Unicorn**
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# **映射内存**
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, CODE)

# **设置 SVC 调用参数**
mu.reg_write(UC_ARM64_REG_X8, 1)  # 系统调用号 (write)
mu.reg_write(UC_ARM64_REG_X30, 0x1000 + len(CODE))  # 返回地址

# **添加 Hook**
hook_id = mu.hook_add(UC_HOOK_INTR, hook_syscall)
print(f"[INFO] Hook 已添加, ID = {hook_id}")

# **运行 Unicorn**
try:
    print("[INFO] 第一次执行:")
    mu.emu_start(0x1000, 0x1000 + len(CODE))

    # **移除 Hook**
    mu.hook_del(hook_id)
    print("[INFO] Hook 已移除")

    # **重新执行 (Hook 不再触发)**
    print("[INFO] 第二次执行:")
    mu.reg_write(UC_ARM64_REG_X8, 1)  # 重新设置系统调用号
    mu.emu_start(0x1000, 0x1000 + len(CODE))

except UcError as e:
    print(f"[ERROR] Unicorn 运行错误: {e}")
```


输出如下：

```
[INFO] Hook 已添加, ID = 2896374788624
[INFO] 第一次执行:
[HOOK] 捕获系统调用: X8 = 1
[模拟] 执行 write 系统调用
[INFO] Hook 已移除
[INFO] 第二次执行:
[ERROR] Unicorn 运行错误: Unhandled CPU exception (UC_ERR_EXCEPTION)
```
第二次执行时崩溃，因为 SVC 指令触发了系统调用，而 Hook 已移除，没有模拟返回值，导致 CPU 异常 (UC_ERR_EXCEPTION)。



