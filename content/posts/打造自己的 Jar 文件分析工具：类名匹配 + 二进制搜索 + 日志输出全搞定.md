+++
title = '打造自己的 Jar 文件分析工具：类名匹配 + 二进制搜索 + 日志输出全搞定'
date = 2025-07-20T23:11:43.193890+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# 前言



在逆向分析、APK 解包或 Java 工程排查中，我们常常需要检查某个 .class 文件是否存在于某个 JAR 包中，或者判断某个关键字是否被硬编码在类的字节码里。



如何通过编写 Python 脚本，帮助你在 JAR 文件中快速定位类、字段，甚至二进制内容。



# 类路径匹配（路径前缀）



JAR 文件本质是 ZIP 文件，通过 zipfile.ZipFile 解压后可遍历所有文件名（也就是 .class 路径），我们只需检查是否以某个前缀开头即可。

```
with zipfile.ZipFile(jar_path, 'r') as jar:
    for entry in jar.namelist():
        if entry.endswith(".class") and entry.startswith(class_prefix_path):
            print(f"[✓] Found in: {jar_path} → {entry}")
            found.append((jar_path, entry))
```


# 字节码字段查找（二进制匹配）



通过读取 .class 文件的二进制数据，可以判断是否存在某个硬编码字符串。比如我们要查找 "VERSION_NAME" 是否被写入类的常量池中，就可以用这种方式。

```
with zipfile.ZipFile(jar_path, 'r') as jar:
    for entry in jar.namelist():
        if entry.endswith(".class"):
            try:
                with jar.open(entry) as class_file:
                    content = class_file.read()
                    if keyword.encode() in content:
                        print(f"[✓] Found '{keyword}' in {entry} → {jar_path}")
                        found.append((jar_path, entry))
            except Exception as e:
                print(f"[!] Failed reading {entry} in {jar_path}: {e}")
```
注意：这是字节级别的搜索，类似 strings 工具。



# 路径与内容联合搜索（双重匹配）



同时检查路径与二进制内容，适合用于广泛关键词搜索。

```
# ① 类名路径中包含关键字
if keyword_path in entry:
    print(f"[✓] Keyword in class name: {entry} ({jar_path})")
    matched = True

# ② 字节码中包含关键字（如字符串常量）
try:
    with jar.open(entry) as class_file:
        content = class_file.read()
        if keyword_bin in content:
            print(f"[✓] Keyword in class bytecode: {entry} ({jar_path})")
            matched = True
except Exception as e:
    print(f"[!] Failed reading {entry} in {jar_path}: {e}")
```


# 编写命令行工具入口



使用 argparse.ArgumentParser 创建参数解析器：

1、directory：要搜索的目录路径，传入的是目录中含有 .jar 文件的位置。

2、keyword：搜索关键字，用于匹配类路径（如 com/example/MyClass）或字节码中的字段内容（如某个字符串、变量名等）。

3、--mode：搜索模式，默认是 "class"，也可以指定为：

- "class"：只搜索类路径名中是否包含关键字。

- "field"：只搜索 .class 文件中的字段、方法等内容（二进制搜索）。

- "all"：两者都搜。

```
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Search for class name or class content keyword in JAR files.")
    parser.add_argument("directory", help="Directory to search")
    parser.add_argument("keyword", help="Class prefix or bytecode keyword")
    parser.add_argument("--mode", choices=["class", "field", "all"], default="class",
                        help="Search mode: 'class' (class path), 'field' (bytecode), 'all' (both)")

    args = parser.parse_args()

    if args.mode == "class":
        find_class_in_jars(args.directory, args.keyword)
    elif args.mode == "field":
        find_field_in_jars(args.directory, args.keyword)
    elif args.mode == "all":
        find_class_and_content_in_jars(args.directory, args.keyword)
```


# 使用示例



## 1. 查找类



查找类是否存在，比如 com.bytedance.retrofit2.SsResponse

```
(anti-app) PS D:\Python\anti-app\dex2jar> python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" "com.bytedance.retrofit2.SsResponse"
[+] Searching for class prefix: com/bytedance/retrofit2/SsResponse
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes28.jar → com/bytedance/retrofit2/SsResponse.class
[+] Total 1 match(es) found.
```


支持模糊查找，比如查找 com.bytedance.ttnet 包下所有类

```
(anti-app) PS D:\Python\anti-app\dex2jar> python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" "com.bytedance.ttnet."
[+] Searching for class prefix: com/bytedance/ttnet/
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes2.jar → com/bytedance/ttnet/TTNetInit$ENV.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes23.jar → com/bytedance/ttnet/debug/DebugSetting.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/http/HttpRequestInfo.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/http/RequestContext.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/HttpClient.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/ITTNetDepend.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/TTALog.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/TTMultiNetwork.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/TTNetInit.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/clientkey/ClientKeyManager.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/config/AppConfig.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/config/TTHttpCallThrottleControl$DelayMode.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/config/TTHttpCallThrottleControl.class        
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/cronet/AbsCronetDependAdapter.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/diagnosis/TTNetDiagnosisService.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/priority/TTHttpCallPriorityControl$ModeType.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/priority/TTHttpCallPriorityControl.class      
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/retrofit/SsInterceptor.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/retrofit/SsRetrofitClient.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/throttle/TTNetThrottle.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/tnc/TNCManager$TNCUpdateSource.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/tnc/TNCManager.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/utils/RetrofitUtils$CompressType.class        
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes37.jar → com/bytedance/ttnet/utils/RetrofitUtils.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes47.jar → com/bytedance/ttnet/diagnosis/IDiagnosisRequest.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes47.jar → com/bytedance/ttnet/diagnosis/IDiagnosisCallback.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes47.jar → com/bytedance/ttnet/diagnosis/TTGameDiagnosisService.class        
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes49.jar → com/bytedance/ttnet/http/IRequestHolder.class
[✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes7.jar → com/bytedance/ttnet/INetworkApi.class
[+] Total 29 match(es) found.
```


## 2. 查找类字节码



查找类字节码中是否包含指定字段（如 VERSION_NAME）

```
(anti-app) PS D:\Python\anti-app\dex2jar> python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" VERSION_NAME --mode field
[✓] Found 'VERSION_NAME' in com/bykv/vk/openvk/api/proto/BuildConfig.class → D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk.jar
[✓] Found 'VERSION_NAME' in com/byted/cast/proxy/BuildConfig.class → D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk.jar
[✓] Found 'VERSION_NAME' in com/ss/ttm/player/TTPlayerConfiger.class → D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes9.jar
. . . . . .
[+] Total 128 matches found.
```


## 3. 类路径与字节码联合搜索



同时查找类路径和字节码是否包含关键词

```
(anti-app) PS D:\Python\anti-app\dex2jar> python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" Retrofit --mode all                   
[+] Searching for class path or class bytecode containing: Retrofit
[✓] Keyword in class bytecode: X/01Ek.class (D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk.jar)
[✓] Keyword in class name: com/bytedance/android/live/broadcast/api/BroadcastConfigRetrofitApi.class (D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk.jar)
. . . . . .
[✓] Keyword in class bytecode: X/0ppk.class (D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes27.jar)
[✓] Keyword in class bytecode: kotlin/jvm/internal/ALambdaS879S0100000_16.class (D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes9.jar)
[+] Total 1639 match(es) found.
[+] Matched JAR count: 49
[+] Matched JAR files:
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes2.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes3.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes4.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes5.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes6.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes7.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes8.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes9.jar
    - D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes10.jar
    . . . . . .
```


# 将日志同时输出到 终端和日志文件



为了将日志同时输出到 终端和指定的日志文件，可以引入 Python 标准库的 logging 模块，并通过一个命令行参数 --logfile 来控制输出日志文件路径。



## 1. 顶部导入 logging 模块

```
import logging
```


## 2. 添加日志初始化函数



在文件顶部添加如下函数来配置日志输出：

```
def setup_logger(logfile: str = None):
    """
    设置日志输出，可选输出到文件。
    :param logfile: 日志文件路径（可选）
    """
    log_format = "[%(asctime)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),  # 控制台输出
            logging.FileHandler(logfile, mode='w', encoding='utf-8') if logfile else logging.NullHandler()
        ]
    )
```
#### 

## 3. 替换 print(...) 为 logging.info(...) 或 logging.warning(...)



例如：

```
print(f"[+] Searching for class prefix: {class_prefix_path}")
```
替换为：

```
logging.info(f"Searching for class prefix: {class_prefix_path}")
```


## 4. 修改 __main__ 中增加参数并初始化日志

```
parser.add_argument("--logfile", help="Log output to specified file (optional)")
```


然后在解析参数之后调用：

```
setup_logger(args.logfile)
```


## 测试



调用时在调用命令后加上 --logfile log.txt

```
python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" "com.bytedance.retrofit2.SsResponse" --logfile log.txt
```


终端和 log.txt 都会输出日志信息。

```
(anti-app) PS D:\Python\anti-app\dex2jar> python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" "com.bytedance.retrofit2.SsResponse" --logfile log.txt
[2025-07-20 22:27:57,695] [+] Searching for class prefix: com/bytedance/retrofit2/SsResponse
[2025-07-20 22:27:58,796] [✓] Found in: D:\Python\anti-app\app\douyin\dump_dex\jar\base.apk_classes28.jar → com/bytedance/retrofit2/SsResponse.class
[2025-07-20 22:28:00,267] [+] Total 1 match(es) found.
```


log.txt



![word/media/image1.png](data:image/png;base64,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)


# 完整源码



```
import logging
import os
import re
import zipfile
from typing import List


def setup_logger(logfile: str = None):
    """
    设置日志输出，可选输出到文件。
    :param logfile: 日志文件路径（可选）
    """
    log_format = "[%(asctime)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),  # 控制台输出
            logging.FileHandler(logfile, mode='w', encoding='utf-8') if logfile else logging.NullHandler()
        ]
    )


def find_class_in_jars(directory, class_prefix):
    """
    查找所有包含指定类名前缀的 .class 文件（支持包名或类名前缀匹配）

    :param directory: 要扫描的目录
    :param class_prefix: 类名或包名前缀（如 com.example. 或 com.example.MyClass）
    """
    if not class_prefix:
        logging.info("[-] Class name prefix cannot be empty.")
        return

    # 将类名转换为 JAR 中的路径格式（例如 com.example. → com/example/）
    class_prefix_path = class_prefix.replace('.', '/')

    logging.info(f"[+] Searching for class prefix: {class_prefix_path}")
    found = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".jar"):
                jar_path = os.path.join(root, file)
                try:
                    with zipfile.ZipFile(jar_path, 'r') as jar:
                        for entry in jar.namelist():
                            if entry.endswith(".class") and entry.startswith(class_prefix_path):
                                logging.info(f"[✓] Found in: {jar_path} → {entry}")
                                found.append((jar_path, entry))
                except zipfile.BadZipFile:
                    logging.info(f"[!] Skipping corrupted jar: {jar_path}")

    if not found:
        logging.info("[-] No matching class found.")
    else:
        logging.info(f"[+] Total {len(found)} match(es) found.")


def find_field_in_jars(directory, keyword):
    """
    在指定目录下所有 jar 文件中查找包含指定字段的类（.class）文件

    :param directory: 待扫描目录路径
    :param keyword: 要查找的字段字符串（如 VERSION_NAME）
    """
    found = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".jar"):
                jar_path = os.path.join(root, file)
                try:
                    with zipfile.ZipFile(jar_path, 'r') as jar:
                        for entry in jar.namelist():
                            if entry.endswith(".class"):
                                try:
                                    with jar.open(entry) as class_file:
                                        content = class_file.read()
                                        if keyword.encode() in content:
                                            logging.info(f"[✓] Found '{keyword}' in {entry} → {jar_path}")
                                            found.append((jar_path, entry))
                                except Exception as e:
                                    logging.info(f"[!] Failed reading {entry} in {jar_path}: {e}")
                except zipfile.BadZipFile:
                    logging.info(f"[!] Bad JAR file: {jar_path}")

    if not found:
        logging.info(f"[-] No classes containing '{keyword}' found.")
    else:
        logging.info(f"\n[+] Total {len(found)} matches found.")

    return found


def sort_jar_paths(jar_paths: List[str]) -> List[str]:
    """
    对包含 base.apk、base.apk_classesN.jar 的路径列表进行排序，确保 _classes2 排在 _classes10 前面。

    :param jar_paths: 未排序的 jar 文件路径列表
    :return: 排序后的 jar 文件路径列表
    """

    def extract_index(path: str) -> int:
        """
        提取路径中 _classesN 的 N 数字部分用于排序。
        如果是 base.apk.jar 则返回 0，表示优先排序。
        """
        match = re.search(r'_classes(\d+)\.jar$', path)
        if match:
            return int(match.group(1))  # 提取 _classesN 中的 N
        return 0  # base.apk.jar 没有 _classesN，默认最小值

    # 按照提取出的数字索引进行排序
    return sorted(jar_paths, key=extract_index)


def find_class_and_content_in_jars(directory, keyword):
    """
    在指定目录下所有 JAR 中搜索：
    1. 类路径中包含关键字的类名
    2. 类的字节码中包含关键字内容

    :param directory: 要搜索的目录
    :param keyword: 要查找的关键字（支持类名路径或内容关键字）
    """
    if not keyword:
        logging.info("[-] 关键词不能为空")
        return

    logging.info(f"[+] Searching for class path or class bytecode containing: {keyword}")

    keyword_bin = keyword.encode()  # 转为二进制用于内容匹配
    keyword_path = keyword.replace('.', '/')

    matched_entries = []
    matched_jars = set()

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".jar"):
                jar_path = os.path.join(root, file)
                try:
                    with zipfile.ZipFile(jar_path, 'r') as jar:
                        for entry in jar.namelist():
                            if not entry.endswith(".class"):
                                continue

                            matched = False

                            # ① 类名路径中包含关键字
                            if keyword_path in entry:
                                logging.info(f"[✓] Keyword in class name: {entry} ({jar_path})")
                                matched = True

                            # ② 字节码中包含关键字（如字符串常量）
                            try:
                                with jar.open(entry) as class_file:
                                    content = class_file.read()
                                    if keyword_bin in content:
                                        logging.info(f"[✓] Keyword in class bytecode: {entry} ({jar_path})")
                                        matched = True
                            except Exception as e:
                                logging.info(f"[!] Failed reading {entry} in {jar_path}: {e}")

                            if matched:
                                matched_entries.append((jar_path, entry))
                                matched_jars.add(jar_path)

                except zipfile.BadZipFile:
                    logging.info(f"[!] Skipping corrupted jar: {jar_path}")

    if not matched_entries:
        logging.info(f"[-] No match found for keyword '{keyword}'")
    else:
        logging.info(f"\n[+] Total {len(matched_entries)} match(es) found.")
        logging.info(f"[+] Matched JAR count: {len(matched_jars)}")
        logging.info("[+] Matched JAR files:")
        for jar_file in sort_jar_paths(matched_jars):
            logging.info(f"    - {jar_file}")


if __name__ == "__main__":
    r"""
    示例用法（支持按类路径、类字段内容或同时匹配进行搜索）：

    1. 按类路径查找（是否包含某类）：
        python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" com.bytedance.retrofit2.SsResponse

       支持包名前缀模糊查找：
        python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" com.bytedance.ttnet.

    2. 按字节码内容查找（如字符串常量、字段名等）：
        python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" VERSION_NAME --mode field

    3. 同时查找类路径和字节码中是否包含关键词：
        python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" com.bytedance.retrofit2.Retrofit --mode all

    4. 输出结果到日志文件（可与以上任意命令组合）：
        python find_in_jars.py "D:\Python\anti-app\app\douyin\dump_dex\jar" com.bytedance.ttnet. --mode all --logfile log.txt
    """
    import argparse

    parser = argparse.ArgumentParser(description="Search for class name or class content keyword in JAR files.")
    parser.add_argument("directory", help="Directory to search")
    parser.add_argument("keyword", help="Class prefix or bytecode keyword")
    parser.add_argument("--mode", choices=["class", "field", "all"], default="class",
                        help="Search mode: 'class' (class path), 'field' (bytecode), 'all' (both)")
    parser.add_argument("--logfile", help="Log output to specified file (optional)")

    args = parser.parse_args()

    # 初始化日志
    setup_logger(args.logfile)

    if args.mode == "class":
        find_class_in_jars(args.directory, args.keyword)
    elif args.mode == "field":
        find_field_in_jars(args.directory, args.keyword)
    elif args.mode == "all":
        find_class_and_content_in_jars(args.directory, args.keyword)
```


开源地址：[https://github.com/CYRUS-STUDIO/dex2jar](https://github.com/CYRUS-STUDIO/dex2jar)



