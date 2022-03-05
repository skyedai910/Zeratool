from pwn import *


def getProperties(binary_name):

    properties = {}
    binary = ELF(binary_name)
    properties["aslr"] = binary.aslr
    properties["arch"] = binary.arch
    properties["canary"] = binary.canary
    properties["got"] = binary.got
    properties["nx"] = binary.nx
    properties["pie"] = binary.pie
    properties["plt"] = binary.plt
    properties["relro"] = binary.relro

    print("[+] binary protective:")
    for key,value in properties.items():
        print("[+] {:8}:\t{}".format(key,value))

    return properties
