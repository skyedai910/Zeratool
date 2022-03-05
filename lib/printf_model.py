from pwn import *
import angr
import claripy
import tqdm

# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    # angr数据以byte为最小单位，需要重新切割从bit，再逐字节比较得出字符串长度
    for c in value.chop(8): # Chop by byte
        i += 1
        # TODO satisfiable这里逻辑没有弄明白
        if not state.solver.satisfiable([c != 0x00]):
            print("Found the null at offset : {}".format(i))
            return i-1
    return i


"""
Model either printf("User input") or printf("%s","Userinput")
"""


# angr.procedures.libc.printf.printf:导入动态函数库printf分类下所有函数
# INFO https://github.com/angr/angr-doc/blob/9f803b24598bea3a0f9cc9c728e1465291b5259d/docs/environment.md#dynamic-library-functions---import-dependencies
class printFormat(angr.procedures.libc.printf.printf):
    # hook的是函数
    IS_FUNCTION = True
    # input_index:格式化字符串参数在原函数定义的下标，默认值0
    input_index = 0
    """
    Checks userinput arg
    """

    def __init__(self,input_index):
        # Set user input index for different
        # printf types
        # input_index:格式化字符串参数在原函数定义的下标，默认值0
        self.input_index=input_index
        angr.procedures.libc.printf.printf.__init__(self)

    def checkExploitable(self): 
        # 获取程序对应架构字长
        bits = self.state.arch.bits
        load_len = int(bits / 8)
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        # 格式化字符串参数在原函数定义的下标
        i = self.input_index
        # angr程序状态
        state = self.state
        # 重命名约束求解方法函数
        # solv = state.solver.eval

        # 导入格式化字符串参数
        printf_arg = self.arg(i)

        # Sanity check
        # state.solver.symbolic:判断输入数据是否为符号变量
        # TODO 所有这里是返回T还是F代表有漏洞
        if self.state.solver.symbolic(printf_arg):
            print("printf arg[{}] ptr is symbolic! HOW?".format(i))

        # 基于当前约束进行求解，var_loc是变量地址
        var_loc = state.solver.eval(printf_arg)

        # 测量符号数据长度
        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(var_loc, max_read_len) # 从内存加载数据
        var_len = get_max_strlen(state, var_data)           # 获取长度

        # Reload with just our max len
        var_data = state.memory.load(var_loc, var_len)

        # 将符号(symbolic)数据读取出来
        # symbolic_list记录是可以写入的bit位。True个数==可写入长度
        print("Building list of symbolic bytes")
        symbolic_list = [
            state.memory.load(var_loc + x,1).symbolic
            for x in range(var_len)
        ]
        print("Done Building list of symbolic bytes")

        """
        Iterate over the characters in the string
        Checking for where our symbolic values are
        This helps in weird cases like:

        char myVal[100] = "I\'m cool ";
        strcat(myVal,STDIN);
        printf(myVal);

        寻找最后一个angr符号的位置
        """
        # 查询可以写入的范围
        position = 0
        count = 0
        greatest_count = 0
        # prev_item = symbolic_list[0]
        symbolic_num = 0
        for symbolic in symbolic_list:
            if symbolic:
                symbolic_num += 1
        for i in range(1, symbolic_num):
            # symbolic不为截断符且前后一致
            if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
                count = count + 1
                if count > greatest_count:
                    greatest_count = count
                    position = i - count    # 栈向低地址生长，所以是减
            else:
                if count > greatest_count:
                    greatest_count = count
                    position = i - 1 - count
                    # previous position minus greatest count
                count = 0
        print(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )
        if greatest_count > 0:
            print("position:",position)
            print("greatest_count:",greatest_count)
            print("var_data:",var_data)
            print("var_loc:",hex(var_loc))
            # x86架构格式化字符串
            str_val = b"%lx_"
            # x64架构格式化字符串
            if bits == 64:
                str_val = b"%llx_"
            # var_len->symbolic_num
            # 参数更改测试长度应该是symbolic_list True个数
            # if self.can_constrain_bytes(state,var_data,var_loc, position,var_len,strVal=str_val):
            if self.can_constrain_bytes(state,var_data,var_loc, position,symbolic_num,strVal=str_val):
                print("[+] Can constrain bytes")
                print("[+] Constraining input to leak")

                self.constrainBytes(
                    state,          # 模拟状态
                    var_data,
                    var_loc,        # 写入地址
                    position,
                    var_len,        # 写入长度
                    strVal=str_val, # 写入格式化字符串
                )
                # Verify solution
                # 获取程序输入符号
                # stdin_str = str(state_copy.posix.dumps(0))
                # 提取程序输入方式
                # user_input = self.state.globals["inputType"]
                # if str_val in solv(user_input):
                #     var_value = self.state.memory.load(var_loc)
                #     self.constrainBytes(
                #         self.state, var_value, var_loc, position, var_value_length
                #     )
                # print("[+] Vulnerable path found {}".format(vuln_string))
                user_input = state.globals["user_input"]

                self.state.globals["input"] = state.solver.eval(user_input, cast_to=bytes)
                self.state.globals["type"] = "Format"
                self.state.globals["position"] = position
                self.state.globals["length"] = greatest_count

                return True

        return False

    # 检测是否能够写入约束(格式化字符串)
    def can_constrain_bytes(self, state, symVar, loc, position, length, strVal=b"%x_"):
        # 循环验证每个字节位置能不能写入(添加约束)
        # tqdm进度条库
        for i in tqdm.tqdm(range(length),total=length, desc="Checking Constraints"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i,1)
            # extra_constraints:以元组形式传递约束，该约束会作为判断依据，但不会加载到state(在这里也就是不会修改内存)
            # satisfiable:判断当前约束是否有解
            if not state.solver.satisfiable(extra_constraints=[curr_byte == strVal[strValIndex]]):
                print("{}:error".format(i))
                return False
        return True

    # 进行写入约束(格式化字符串)
    def constrainBytes(self, state, symVar, loc, position, length, strVal=b"%x_"):
        for i in tqdm.tqdm(range(length),total=length, desc="Constraining"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i,1)
            # 对约束条件的可解性进行判断
            # INFO https://www.freebuf.com/vuls/194619.html
            if state.solver.satisfiable(extra_constraints=[curr_byte == strVal[strValIndex]]):
                # 添加约束
                state.add_constraints(curr_byte == strVal[strValIndex])
            else:
                # 异常无法写入
                print(
                    "[~] Byte {} not constrained to {}".format(i, strVal[strValIndex])
                )

    def run(self):
        if not self.checkExploitable():
            # 循环调用printFormat类的run，即循环直到漏洞出现
            return super(type(self), self).run()