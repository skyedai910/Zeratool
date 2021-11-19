import angr
from angr import sim_options as so
# 使用claripy库，将输入的数据符号化
import claripy
import time
import timeout_decorator
import IPython
from .simgr_helper import overflow_detect_filter


def checkOverflow(binary_name, inputType="STDIN"):
    # TODO 属性含义
    # INFO 属性文档:https://github.com/angr/angr-doc/blob/9f803b24598bea3a0f9cc9c728e1465291b5259d/docs/appendices/options.md
    extras = {
        so.REVERSE_MEMORY_NAME_MAP,
        so.TRACK_ACTION_HISTORY,
        so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
    # SimProcedure自定义hook函数
    class hookFour(angr.SimProcedure):
        # hook的是函数
        IS_FUNCTION = True
        # TODO 为什么要禁用随机函数
        def run(self):
            # 固定随机数4
            return 4  # Fair dice roll

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})
    # Hook rands
    # hook随机函数，去随机化
    p.hook_symbol("rand", hookFour)
    p.hook_symbol("srand", hookFour)
    # p.hook_symbol('fgets',angr.SIM_PROCEDURES['libc']['gets']())

    # Setup state based on input type
    argv = [binary_name]
    input_arg = claripy.BVS("input", 300 * 8)
    # INFO 状态预设:https://github.com/angr/angr-doc/blob/079c79b89c044a35f1cc6cb31ab799710f96fede/docs/states.md
    if inputType == "STDIN":
        # full_init_state:构造从初始化开始的状态，完成初始化后跳转entry point
        state = p.factory.full_init_state(args=argv, stdin=input_arg)
        # 在state存储数据，方便数据的调用
        # BUG globals属性有几率不存在
        # INFO https://github.com/angr/angr-doc/blob/9f803b24598bea3a0f9cc9c728e1465291b5259d/docs/state_plugins.md
        # INFO https://github.com/angr/angr-doc/blob/9f803b24598bea3a0f9cc9c728e1465291b5259d/docs/simprocedures.md#global-variables
        state.globals["user_input"] = input_arg
    elif inputType == "LIBPWNABLE":
        # FIXME 如果不存在handle_connection，那么读取rebased_addr
        # handle_connection:socket网络连接相关函数
        handle_connection = p.loader.main_object.get_symbol("handle_connection")
        # entry_state:构造从binary入口开始的状态(从main函数开始运行)
        # handle_connection.rebased_addr:实际上获取text起始地址
        state = p.factory.entry_state(
            addr=handle_connection.rebased_addr, stdin=input_arg, add_options=extras
        )
        state.globals["user_input"] = input_arg
    else:
        argv.append(input_arg)
        state = p.factory.full_init_state(args=argv)
        state.globals["user_input"] = input_arg

    # 修改angr处理符号数量，默认值60:https://github.com/angr/angr/issues/1590#issuecomment-497579181
    state.libc.buf_symbolic_bytes = 0x100
    state.globals["inputType"] = inputType
    # 出现unconstrained，则认为产生漏洞
    simgr = p.factory.simgr(state, save_unconstrained=True)

    run_environ = {}
    run_environ["type"] = None
    end_state = None
    # Lame way to do a timeout
    try:
        # 函数超时处理
        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            # TODO 
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
            )

        exploreBinary(simgr)
        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ["type"] = end_state.globals["type"]

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        print("[~] Overflow check timed out")

    if "input" in run_environ.keys():
        run_environ["input"] = end_state.globals["input"]
        print("[+] Triggerable with input : {}".format(end_state.globals["input"]))

    return run_environ
