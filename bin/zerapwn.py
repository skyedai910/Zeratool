#!/usr/bin/env python3
# 适配Python2括号问题
from __future__ import print_function
# 校验radare2是否安装
from shutil import which
import argparse
import logging
import os

#logging.disable(logging.CRITICAL)
from zeratool import formatDetector
from zeratool import formatLeak
from zeratool import inputDetector
from zeratool import overflowDetector
from zeratool import overflowExploiter
from zeratool import overflowExploitSender
from zeratool import protectionDetector
from zeratool import winFunctionDetector
from zeratool import formatExploiter

logging.getLogger().disabled = True

# 校验radare2是否安装
def is_radare_installed():
    return which("r2") != None

def main():
    # 校验radare2是否安装
    if not is_radare_installed():
        print("[-] Error radare2 is not installed.")
        exit(1)

    # 创建命令行参数解析器
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-l", "--libc", help="libc to use")
    parser.add_argument("-u", "--url", help="Remote URL to pwn", default="")
    parser.add_argument("-p", "--port", help="Remote port to pwn", default="0")
    # 详细模式：默认开启，有值时action记录为False
    parser.add_argument(
        "-v", "--verbose", help="Close verbose mode", action="store_true", default=False
    )

    args = parser.parse_args()
    # 未找到对应文件
    if args.file is None:
        print("[-] Exitting no file specified")
        exit(1)
    # 关闭详细模式
    if args.verbose:
        # 关闭CRITICAL级别以下的日志
        logging.disable(logging.CRITICAL)

    # For stack problems where env gets shifted
    # based on path, using the abs path everywhere
    # makes it consistent
    # 获取文件绝对路径
    args.file = os.path.abspath(args.file)

    # Detect problem type
    # 程序属性存储字典
    properties = {}
    # 程序数据输入方式
    properties["input_type"] = inputDetector.checkInputType(args.file)
    # 程序动态链接库
    properties["libc"] = args.libc
    properties["file"] = args.file
    print("[+] Checking pwn type...")
    print("[+] Checking for overflow pwn type...")
    # 检查是否存在栈溢出
    properties["pwn_type"] = overflowDetector.checkOverflow(
        args.file, inputType=properties["input_type"]
    )
    # 检查是否存在格式化字符串
    if properties["pwn_type"]["type"] is None:
        print("[+] Checking for format string pwn type...")
        properties["pwn_type"] = formatDetector.checkFormat(
            args.file, inputType=properties["input_type"]
        )

    # Get problem mitigations
    # 获取程序保护机制
    print("[+] Getting binary protections")
    properties["protections"] = protectionDetector.getProperties(args.file)

    # Is it a leak based one?
    if properties["pwn_type"]["type"] == "Format":
        print("[+] Checking for flag leak")
        properties["pwn"] = formatLeak.checkLeak(args.file, properties)
        # Launch leak remotely
        if properties["pwn"]["flag_found"] and args.url != "":
            print("[+] Found flag through leaks locally. Launching remote exploit")
            print("[+] Connecting to {}:{}".format(args.url, args.port))
            properties["pwn"]["exploit"] = formatLeak.checkLeak(
                args.file,
                properties,
                remote_server=True,
                remote_url=args.url,
                port_num=int(args.port),
            )
        if properties["pwn"]["flag_found"]:
            exit(0)

    # Is there an easy win function
    properties["win_functions"] = winFunctionDetector.getWinFunctions(args.file)

    # Exploit overflows
    if properties["pwn_type"]["type"] == "Overflow":
        print("[+] Exploiting overflow")
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            args.file, properties, inputType=properties["input_type"]
        )
        if properties["pwn_type"]["results"]["input"]:
            properties["send_results"] = overflowExploitSender.sendExploit(
                args.file, properties
            )
            if properties["send_results"]["flag_found"] and args.url != "":
                properties["remote_results"] = overflowExploitSender.sendExploit(
                    args.file,
                    properties,
                    remote_server=True,
                    remote_url=args.url,
                    port_num=int(args.port),
                )

    elif properties["pwn_type"]["type"] == "Format":
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            args.file, properties
        )
        if (
            properties["pwn_type"] != None
            and "flag_found" in properties["pwn_type"].keys()
            and properties["pwn_type"]["results"]["flag_found"]
            and args.url != ""
        ):
            properties["pwn_type"]["send_results"] = formatExploiter.getRemoteFormat(
                properties, remote_url=args.url, remote_port=int(args.port)
            )
    else:
        print("[-] Can not determine vulnerable type")


if __name__ == "__main__":
    main()
