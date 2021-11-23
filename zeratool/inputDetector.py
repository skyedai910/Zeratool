import angr
import IPython

stdin = "STDIN"
arg = "ARG"
libpwnable = "LIBPWNABLE"


def checkInputType(binary_name):

    # Check for libpwnableharness
    # 导入程序
    p = angr.Project(binary_name)
    # any判断是否全为空
    # 从ELF文件中加载的所有对象(elf,libc,ld)绝对路径，检查是否调用了libpwnable这个库文件
    if any(["libpwnable" in str(x.binary) for x in p.loader.all_elf_objects]):
        return libpwnable

    # 禁止载入依赖库，减少分析工作量，以防程序崩溃
    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    # 控制流程图
    #    CFG = p.analyses.CFGFast()

    # Functions which MIGHT grab from STDIN
    # 能提供stdin输入的函数
    reading_functions = ["fgets", "gets", "scanf", "read", "__isoc99_scanf"]
    # 加载程序全部函数
    #    binary_functions = [str(x[1].name) for x in CFG.kb.functions.items()]
    binary_functions = list(p.loader.main_object.imports.keys())

    # 匹配寻找是否有stdin输入函数
    # Match reading functions against local functions
    if any([x in reading_functions for x in binary_functions]):
        return "STDIN"
    return "ARG"
