+++
title = '详解ARM汇编条件标志'
date = 2024-11-04T20:19:51.993649+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# __条件标志__


在 ARM 指令集中，条件标志是控制指令执行的一种机制，它们用于实现条件分支、比较和其他逻辑操作。

我们平时使用 IDA 调试程序时，在 general registers 窗口中看到的条件标志
![image.png](data:image/png;base64,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)

ARM 处理器通常使用四个主要的条件标志，它们的状态影响指令的执行。这些条件标志包括：

1\. N (Negative): 负标志，用于指示最后一次操作的结果是否为负值。若结果为负，则 N 被置为 1；否则为 0。

2\. Z (Zero): 零标志，用于指示最后一次操作的结果是否为零。如果结果为零，则 Z 被置为 1；否则为 0。

3\. C (Carry): 进位标志，用于指示加法操作是否产生了进位或减法操作是否没有借位。对于加法，若产生进位，则 C 被置为 1；对于减法，若没有借位，则 C 被置为 1。

4\. V (Overflow): 溢出标志，用于指示最后一次算术操作是否发生了溢出。当两个有符号数相加或相减时，如果结果的符号与操作数的符号不一致，表示发生了溢出，V 被置为 1。

在 ARM 指令中，条件执行可以通过附加条件码实现，例如：

- EQ (Equal): 当 Z = 1 时执行（相等）。

- NE (Not Equal): 当 Z = 0 时执行（不相等）。

- GT (Greater Than): 当 Z = 0 且 N = V 时执行（大于）。

- LT (Less Than): 当 N ≠ V 时执行（小于）。

- GE (Greater Than or Equal): 当 N = V 时执行（大于或等于）。

- LE (Less Than or Equal): 当 Z = 1 或 N ≠ V 时执行（小于或等于）。

这些条件标志和条件码使得 ARM 架构能够高效地进行复杂的控制流和决策逻辑，从而优化程序的执行效率。

# __条件标志如何影响指令的执行__


下面以一段汇编代码解释条件标志的变化过程，以及如何通过条件码用于指令影响汇编指令的走向。
```
    .data
a:  .word 5       // 定义变量 a，值为 5
b:  .word 10      // 定义变量 b，值为 10
max_value: .word 0 // 存储最大值的变量

    .text
    .global _start

_start:
    // 读取 a 和 b 的值
    LDR R0, =a        // 将 a 的地址加载到 R0
    LDR R1, [R0]      // 将 a 的值加载到 R1 (R1 = 5)

    LDR R0, =b        // 将 b 的地址加载到 R0
    LDR R2, [R0]      // 将 b 的值加载到 R2 (R2 = 10)

    // 比较 a 和 b
    CMP R1, R2        // 比较 R1 (a) 和 R2 (b)
                       // 根据 R1 和 R2 的值，设置条件标志
                       // 如果 R1 < R2:
                       //   N = 1, Z = 0, C = 1, V = 0
                       // 如果 R1 == R2:
                       //   N = 0, Z = 1, C = 1, V = 0
                       // 如果 R1 > R2:
                       //   N = 0, Z = 0, C = 0, V = 0

    // 根据比较结果设置最大值
    BEQ a_equals_b    // 如果 Z = 1 (相等)，跳转到 a_equals_b
    BGT a_greater      // 如果 N = 0 且 Z = 0，(a > b)，跳转到 a_greater
    // 如果到这里，说明 b > a
    STR R2, =max_value // b 是最大值，存储 b 的值

    B end              // 跳转到 end

a_equals_b:
    // a 和 b 相等
    STR R1, =max_value // 存储任一值，a 或 b 都可以

    B end              // 跳转到 end

a_greater:
    // a 大于 b
    STR R1, =max_value // 存储 a 的值

end:
    // 结束程序
    MOV R7, #1        // 系统调用号，退出
    SWI 0             // 触发系统调用
```

# __CMP 指令是如何影响条件标志__


在 ARM 汇编中，CMP 指令用于比较两个寄存器的值。具体来说，CMP R1,R2 指令会将寄存器 R1 的值减去寄存器 R2 的值，但不会将结果存储在任何寄存器中。这一操作的主要目的是更新条件标志，以便后续的条件执行指令可以根据比较结果做出决策。

我们可以在执行比较 CMP R1, R2 时观察到条件标志的变化。
| 步骤 | R1 (a) | R2 (b) | N (Negative) | Z (Zero) | C (Carry) | V (Overflow) | 说明 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 读取 a 的值 | 5 | - | - | - | - | - | 加载 a 的值到 R1 |
| 读取 b 的值 | 5 | 10 | - | - | - | - | 加载 b 的值到 R2 |
| 比较 R1 和 R2 | 5 | 10 | 1 | 0 | 1 | 0 | 执行 CMP R1, R2 ，结果 5 - 10（借位） |
| BEQ 检查 | 5 | 10 | 1 | 0 | 1 | 0 | Z = 0（不相等），不跳转到 a_equals_b |
| BGT 检查 | 5 | 10 | 1 | 0 | 1 | 0 | N = 1，Z = 0（a 不大于 b），不跳转到 a_greater |
| 存储最大值 | - | 10 | 1 | 0 | 1 | 0 | 存储 b 的值到 max_v |

               

