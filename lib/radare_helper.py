import time
from pwnlib.replacements import sleep
import r2pipe
import json
import os


# BUG 对于PIE程序，getbaseaddr获取的地址和这个r2 debug运行时是不一样的，所以获取的是假的reg值
def getRegValues(filename, endAddr=None, pie=None):
    # r2 = r2pipe.open(filename,flags=["-d"])
    for i in range(10):
        print("[-] try to find entry_addr for {} times".format(i+1))
        entry_addr = None
        r2 = r2pipe.open(filename,flags=["-d"])
        r2.cmd("e dbg.bep=entry")
        try:
            tmp_data = json.loads(r2.cmd("iej"))
            if "vaddr" in tmp_data[0]:
                entry_addr = tmp_data[0]["vaddr"]
                base_addr = entry_addr - tmp_data[0]["paddr"]
                r2.cmd("dcu {}".format(entry_addr))
                break
            else:
                print("[!] radare2 return json [iej] data[0] has not \"vaddr\", trying again")
                r2.quit()
                time.sleep(0.5)
                continue
        except json.decoder.JSONDecodeError:
            print("[!] radare2 return json [iej] data is empty, trying again")
            r2.quit()
            time.sleep(0.5)
            continue
    else:
        print("[!] radare2 rerun multiple times, but can't get data, exitting...")
        exit(-1)

    regs = None
    for _ in range(10):
        if not regs:
            try:
                regs = json.loads(r2.cmd("drj"))
                print("[+] redare2 drj:",regs)
                break
            except json.decoder.JSONDecodeError:
                print("[!] radare2 return json [drj] data is empty, trying again")
                regs = None
                time.sleep(0.5)
    else:
        print("[!] radare2 rerun multiple times, but can't get data, exitting...")
        exit(-1)
    r2.quit()
    if not pie:
        return regs
    else:
        return base_addr,regs


def get_base_addr(filename):
    for _ in range(10):
        r2 = r2pipe.open(filename)
        r2.cmd("doo")   # 这里用doo目的是开启debug模式读取地址信息，普通分析模式是偏移地址（PIE）
        iMj_data = None
        if not iMj_data:
            try:
                iMj_data = json.loads(r2.cmd("iMj"))
                if "vaddr" not in iMj_data and "paddr" not in iMj_data:
                    print("[!] radare2 [iMj] retrun data has no vaddr info, try again")
                    r2.quit()
                    continue
                else:
                    print("[+] redare2 iMj:",iMj_data)
                    break
            except json.decoder.JSONDecodeError:
                    print("[!] radare2 return json [iMj] data is empty, trying again")
                    r2.quit()
                    time.sleep(0.5)
                    continue
            except TypeError:
                    print("[!] radare2 return json [iMj] data is int, trying again")
                    r2.quit()
                    time.sleep(0.5)
                    continue
    else:
        print("[!] radare2 rerun multiple times, but can't get data, exitting...")
        exit(-1)
    base_addr = iMj_data["vaddr"]-iMj_data['paddr']
    print("[+] base_addr:",hex(base_addr))
    return base_addr


"""
This is so hacky. I'm sorry
It's also only for stdin
"""


def findShellcode(filename, endAddr, shellcode, commandInput):

    hex_str = shellcode[:4]
    hex_str = "".join([hex(x).replace("0x", "") for x in hex_str])

    abs_path = os.path.abspath(filename)

    # If you know a better way to direct stdin please let me know
    os.system("env > temp.env")
    with open("command.input", "wb") as f:
        f.write(commandInput)
    with open("temp.rr2", "w") as f:
        # f.write(
        #     "program={}\nstdin=command.input\nenvfile={}\n".format(filename, "temp.env")
        # )
            f.write("program={}\nstdin=command.input\nclearenv=true\nenvfile={}\n".format(abs_path,"temp.env"))

    r2 = r2pipe.open(filename)
    r2.cmd("e dbg.profile = temp.rr2")
    r2.cmd("ood")
    r2.cmd("dcu {}".format(endAddr))
    r2.cmd("s ebp")
    r2.cmd("e search.maxhits =1")
    r2.cmd("e search.in=dbg.map")  # Need to specify this for r2pipe

    loc = json.loads(r2.cmd("/xj {}".format(hex_str)))

    # Cleaning up
    if os.path.exists("command.input"):
        os.remove("command.input")
    if os.path.exists("temp.rr2"):
        os.remove("temp.rr2")
    if os.path.exists("temp.env"):
        os.remove("temp.env")

    return loc[0]
