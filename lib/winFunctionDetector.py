import r2pipe
import json
import time

def getWinFunctions(binary_name):

    winFunctions = {}

    # Initilizing r2 with with function call refs (aac)
    r2 = r2pipe.open(binary_name)
    # aaa对程序进行分析,类似于ida
    r2.cmd("aaa")

    # afl列出程序存在的函数；j设定返回json格式
    functions = []
    for _ in range(10):
        if not len(functions):
            try:
                functions = [func for func in json.loads(r2.cmd("aflj"))]
                # print("[+] redare2 aflj:",functions)
                break
            except json.decoder.JSONDecodeError:
                print("[!] radare2 return json [aflj] data is empty, trying again")
                time.sleep(0.5)
                continue
    else:
        print("[!] radare2 rerun multiple times, but can't get data, exitting...")
        exit(-1)

    # Check for function that gives us system(/bin/sh)
    for func in functions:
        if "system" in str(func["name"]):
            system_name = func["name"]

            # Get XREFs
            # 查询函数调用位置，相当于ida交叉引用
            refs = [
                func for func in json.loads(r2.cmd("axtj @ {}".format(system_name)))    # @ 可去除
            ]
            # 提取上层调用函数fcn_name
            for ref in refs:
                if "fcn_name" in ref:
                    winFunctions[ref["fcn_name"]] = ref
                    # dict example:winFunctions["sym.handle_connection"]="sym.imp.__isoc99_scanf"

    # Check for function that reads flag.txt
    # Then prints flag.txt to STDOUT
    known_flag_names = ["flag", "pass", "sh", "flag.txt"]

    # iz列出程序存在的字符串；j设定返回json格式
    strings = []
    for _ in range(10):
        if not len(strings):
            try:
                strings = [string for string in json.loads(r2.cmd("izj"))]
                # 返回数据中没有 string 字段，重新运行一遍
                if "string" in strings[0]:  
                    print("[+] redare2 izj:",strings)
                    break
                else:
                    print("[!] radare2 return json [izj] data has not \"string\", trying again")
                    strings = []
            except json.decoder.JSONDecodeError:
                print("[!] radare2 return json [izj] data is empty, trying again")
                time.sleep(0.5)
                continue
            except IndexError:
                print("[!] program have no any strings")
                return winFunctions
    else:
        print("[!] radare2 rerun multiple times, but can't get data, exitting...")
        exit(-1)

    for string in strings:
        value = string["string"]
        # 检测字符串是否含有目标字符
        if any([x in value for x in known_flag_names]):
            address = string["vaddr"]   #提取字符串绝对地址
            # Get XREFs
            # 交叉引用查询字符串被调用的函数
            refs = [func for func in json.loads(r2.cmd("axtj @ {}".format(address)))]

            for ref in refs:
                if "fcn_name" in ref:
                    winFunctions[ref["fcn_name"]] = ref
            
        else:
            print("[-]can't find known_flag_names in the program")

    # TODO 这里找后门方法很奇怪，从函数名出发找了一堆，从字符串又找了一堆，但是万一是函数参数分离怎么判断
    for key, value in winFunctions.items():
        print("[+] Found win function:{}({})-->{}({})".format(
            key,hex(value['fcn_addr']),value['fcn_name'],hex(value['from'])
            ))
    return winFunctions
