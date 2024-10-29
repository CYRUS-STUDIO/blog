+++
title = 'frida脚本，自动化寻址JNI方法'
date = 2024-10-29T16:59:40.349565+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>


1\. 通过 ArtMethod 结构体找到 jni 方法在内存中的地址，并把寻址方法通过 rpc.exports 暴露给 Python 脚本调用

jni_addr.js
```
let entry_point_from_jni_offset = -1;

/**
 * 找到 entry_point_from_jni_ 在 ArtMethod 结构体中的偏移量（根据 Android 版本不同可能会变化）
 *
 * @returns {number} 返回 entry_point_from_jni_ 的偏移量，若未找到返回 -1
 */
function get_jni_offset() {

    // 如果偏移量已经计算过（不为 -1），直接返回已保存的偏移量
    if (entry_point_from_jni_offset !== -1) {
        return entry_point_from_jni_offset;
    }

    // 获取 getUidForName JNI 方法的内存地址，该方法位于 "libandroid_runtime.so" 中
    let native_addr = Module.findExportByName("libandroid_runtime.so", "_Z32android_os_Process_getUidForNameP7_JNIEnvP8_jobjectP8_jstring");
    // console.log("native_addr:",native_addr);

    // 目标类名 "android.os.Process"
    let className = "android.os.Process";
    // 使用 Java.use 获取该类的 Java 类对象，并访问其 Class 对象
    let clazz = Java.use(className).class;
    // 获取该类的所有声明的方法
    let methods = clazz.getDeclaredMethods();

    // 遍历类中的所有方法
    for (let i = 0; i < methods.length; i++) {

        // 获取方法的字符串表示形式（如方法的完整签名）
        let methodName = methods[i].toString();

        // 获取方法的修饰符，flags 是该方法的访问标志（修饰符），如 public、private、static、native 等
        let flags = methods[i].getModifiers();

        // 通过与 256 位运算判断方法是否为 native 方法（256 代表 native 修饰符）
        if (flags & 256) {

            // 如果方法名中包含 "getUidForName"，说明找到了目标方法
            if (methodName.indexOf("getUidForName") != -1) {

                // 获取该方法的 ArtMethod 对象（ArtMethod 是方法的内部表示，包含了方法的很多底层信息）
                let art_method = methods[i].getArtMethod();

                // 遍历从 ArtMethod 开始的内存地址，以找到与 native_addr 相等的 JNI 函数地址
                for (let j = 0; j < 30; j = j + 1) {

                    // 读取 ArtMethod 的内存偏移位置，尝试获取 JNI 函数地址
                    let jni_native_addr = Memory.readPointer(ptr(art_method + j));

                    // 比较 JNI 函数地址是否与我们查找到的 native_addr 相等
                    if (native_addr.equals(jni_native_addr)) {
                        // 找到正确的偏移量，将其保存并返回
                        entry_point_from_jni_offset = j;
                        return j;
                    }
                }
            }
        }
    }

    // 如果未找到 JNI 方法对应的偏移量，返回 -1
    return -1;
}

/**
 * 遍历类中的 native 方法，打印 JNI 函数的地址、所属模块，以及模块中的偏移量。
 *
 * 调用示例：get_jni_method_addr("lte.NCall")
 *
 * @param className 类名
 */
function get_jni_method_addr(className) {
    Java.perform(function () {
        // 获取指定类的 Class 对象
        let obj = Java.use(className);
        let clazz = obj.class;

        // 获取当前系统的 JNI 偏移量
        let jni_offset = get_jni_offset();

        // 获取该类中的所有声明的方法
        let methods = clazz.getDeclaredMethods();

        // 遍历类中的所有方法
        for (let i = 0; i < methods.length; i++) {

            // 将方法转为字符串形式（完整的描述，包括修饰符、返回类型、参数等）
            let methodName = methods[i].toString();

            // 获取方法的修饰符，flags 代表访问权限和其他属性（如 native 修饰符）
            let flags = methods[i].getModifiers();

            // 检查该方法是否为 native 方法（通过与 256 位运算判断，256 代表 native 修饰符）
            if (flags & 256) {

                // 获取该方法的 ArtMethod 对象，ArtMethod 是方法在 ART 虚拟机中的内部表示
                let art_method = methods[i].getArtMethod();

                // 通过 ArtMethod 的内存地址 + jni_offset = JNI 函数地址
                let native_addr = Memory.readPointer(ptr(art_method + jni_offset));

                // 根据 JNI 函数地址中找到所在的模块，并计算该函数在模块中的偏移量
                let module;
                let offset;

                // 打印方法名
                console.log("methodName->", methodName);
                try {
                    // 通过函数地址找到所属的模块
                    module = Process.getModuleByAddress(native_addr);

                    // 计算函数在模块中的偏移量（函数地址减去模块基地址）
                    offset = native_addr - module.base;

                    // 打印模块名称及偏移量，偏移量以十六进制格式显示，并且字母大写
                    console.log("Func.offset==", module.name, "0x" + offset.toString(16).toUpperCase());
                } catch (err) {

                }

                // 打印该方法的 JNI 函数地址
                console.log("Func.getArtMethod->native_addr:", native_addr.toString().toUpperCase());

                printModuleInfo(native_addr)

                // console.log("Func.flags->", flags);
            }
        }
    })
}


/**
 * 根据函数地址打印所在模块信息
 *
 * @param address 函数内存地址
 */
function printModuleInfo(address) {
    // 将传入的地址转换为 Frida 可处理的指针类型
    const targetAddress = ptr(address);

    // 查找该地址所在的模块
    const module = Process.findModuleByAddress(targetAddress);

    if (module !== null) {
        console.log("[+] 地址 " + targetAddress + " 所在模块信息：");
        console.log("    - 模块名称: " + module.name);
        console.log("    - 基址: " + module.base);
        console.log("    - 大小: " + module.size + " bytes");
        // console.log("    - 文件路径: " + module.path);

        // 遍历并打印该模块的所有导出符号
        // console.log("    - 导出符号:");
        // module.enumerateExports().forEach(function (exp) {
        //     console.log("        " + exp.name + " @ " + exp.address);
        // });
    } else {
        console.log("[-] 无法找到该地址所在的模块。请检查地址是否正确。");
    }
}

// 暴露给 Python 调用（注意：exports中函数名需要全部小写，而且不能有下划线，不然会找不到方法）
rpc.exports.getjnimethodaddr = get_jni_method_addr
```

2\. 在 python 脚本中加载 jni_addr.js 并调用 get_jni_method_addr 方法打印指定类中所有 native 方法的内存地址

jni_addr.py
```
import frida


def read_frida_js_source(script):
    with open(script, "r", encoding='utf-8') as f:
        return f.read()


def on_message(message, data):
    print(f"消息: {message['type']}, 数据: {message['payload']}")


def main():
    class_name = "com.cyrus.example.MainActivity"

    device = frida.get_device_manager().add_remote_device("127.0.0.1:1234")
    pid = device.get_frontmost_application().pid
    session: frida.core.Session = device.attach(pid)
    script = session.create_script(read_frida_js_source("jni_addr.js"))
    script.on('message', on_message)
    script.load()

    script.exports.getjnimethodaddr(class_name)

    # 退出
    session.detach()


if __name__ == "__main__":
    main()
```

运行python脚本，执行结果如下
```
methodName-> public static native java.lang.Object lte.NCall.IL(java.lang.Object[])
Func.offset== libGameVMP.so 0xDFA8
Func.getArtMethod->native_addr: 0X747DB9AFA8
[+] 地址 0x747db9afa8 所在模块信息：

-     - 模块名称: libGameVMP.so

-     - 基址: 0x747db8d000

-     - 大小: 462848 bytes
```

具体原理可以参考这篇文章【[使用 Frida 定位 JNI 方法内存地址](https://cyrus-studio.github.io/blog/posts/%E4%BD%BF%E7%94%A8-frida-%E5%AE%9A%E4%BD%8D-jni-%E6%96%B9%E6%B3%95%E5%86%85%E5%AD%98%E5%9C%B0%E5%9D%80/)】


               

