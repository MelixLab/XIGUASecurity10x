#!/usr/bin/env python3
"""
感染型病毒模拟器 - 用于测试杀毒软件的感染型病毒检测功能

这个工具模拟感染型病毒的行为：
1. 在PE文件末尾添加一个新的节区
2. 修改入口点指向新节区
3. 在新节区写入病毒代码：显示弹窗后跳回原始程序

警告：此工具仅用于测试和教育目的，请勿用于恶意用途！
"""

import sys
import os
import struct
import random
import string
import subprocess
import tempfile
from datetime import datetime


def generate_virus_section_name():
    """生成病毒节区名称 - 使用明显的恶意节区名"""
    virus_names = [
        '.virus',
        '.infected', 
        '.vir',
        '.malware',
        '.trojan',
        '.payload',
        '.evil',
        '.hack',
    ]
    return random.choice(virus_names)


def align_up(value, alignment):
    """向上对齐"""
    return (value + alignment - 1) & ~(alignment - 1)


def create_virus_shellcode(original_entry_point_va, image_base):
    """
    创建病毒shellcode - 包含明显的病毒特征，能被杀毒软件检测
    
    特征：
    1. 包含已知的病毒行为模式代码
    2. 包含病毒常用的字符串
    3. 保存原始入口点并跳转回去
    """
    
    entry_point_abs = image_base + original_entry_point_va
    
    # 构建包含病毒特征的shellcode
    # 这些特征会被杀毒软件识别为感染型病毒
    
    shellcode = bytearray()
    
    # ==== 病毒签名标记 (杀毒软件会识别这些标记) ====
    # 添加已知的病毒签名模式
    virus_signatures = [
        b'\x4D\x5A\x90\x00',  # 假的MZ头标记
        b'VIRUS_SIGNATURE',   # 病毒签名字符串
        b'INFECTED_MARKER',   # 感染标记
        b'EP_HIJACKED',       # 入口点劫持标记
    ]
    
    # ==== 保存寄存器和设置栈帧 ====
    shellcode.extend([
        0x55,                           # push rbp
        0x48, 0x89, 0xE5,               # mov rbp, rsp
        0x48, 0x83, 0xEC, 0x40,         # sub rsp, 0x40
        0x53,                           # push rbx
        0x56,                           # push rsi
        0x57,                           # push rdi
        0x41, 0x54,                     # push r12
        0x41, 0x55,                     # push r13
        0x41, 0x56,                     # push r14
        0x41, 0x57,                     # push r15
    ])
    
    # 保存原始入口点到r15
    shellcode.extend([0x49, 0xBF])     # mov r15, imm64
    shellcode.extend(struct.pack('<Q', entry_point_abs))
    
    # ==== 病毒行为模拟代码 ====
    # 这段代码模拟病毒的典型行为模式，会被杀毒软件识别
    
    # 1. PEB遍历代码 (病毒常用技术)
    shellcode.extend([
        # 获取PEB - 病毒常用技术
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        # 检查BeingDebugged标志 (反调试)
        0x48, 0x8B, 0x40, 0x18,
        0x80, 0x78, 0x02, 0x00,         # cmp byte [rax+0x2], 0
        # 获取模块列表
        0x48, 0x8B, 0x40, 0x20,
    ])
    
    # 2. 添加病毒特征指令序列
    # 这些指令序列常见于感染型病毒
    shellcode.extend([
        # 解密循环 (病毒常用)
        0x31, 0xC9,                     # xor ecx, ecx
        0x31, 0xDB,                     # xor ebx, ebx
        0x31, 0xD2,                     # xor edx, edx
        # 多态代码标记
        0xEB, 0x02,                     # jmp short
        0x90, 0x90,                     # nop nop
    ])
    
    # 3. 添加已知的恶意代码模式
    # 这些模式会被杀毒软件的启发式引擎识别
    malicious_patterns = bytes([
        # 创建远程线程模式
        0x48, 0xC7, 0xC1, 0x00, 0x10, 0x00, 0x00,  # mov rcx, 0x1000
        0x48, 0xC7, 0xC2, 0x00, 0x30, 0x00, 0x00,  # mov rdx, 0x3000
        
        # 内存修改模式 (VirtualProtect风格)
        0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,        # mov r8d, 0x40 (PAGE_EXECUTE_READWRITE)
        
        # 代码注入模式
        0x48, 0x89, 0x4C, 0x24, 0x20,   # mov [rsp+0x20], rcx
        0x48, 0x89, 0x54, 0x24, 0x28,   # mov [rsp+0x28], rdx
    ])
    shellcode.extend(malicious_patterns)
    
    # 4. 添加病毒字符串 (会被字符串扫描器识别)
    virus_strings = b'CreateRemoteThread\x00VirtualAlloc\x00WriteProcessMemory\x00'
    
    # 5. 添加感染标记
    infection_marker = b'[XIGUASecurity_Infected_Test_File]\x00'
    
    # ==== 恢复寄存器并跳转回原始入口点 ====
    shellcode.extend([
        # 恢复寄存器
        0x41, 0x5F,                     # pop r15
        0x41, 0x5E,                     # pop r14
        0x41, 0x5D,                     # pop r13
        0x41, 0x5C,                     # pop r12
        0x5F,                           # pop rdi
        0x5E,                           # pop rsi
        0x5B,                           # pop rbx
        0x48, 0x89, 0xEC,               # mov rsp, rbp
        0x5D,                           # pop rbp
        
        # 跳转到原始入口点
        0x49, 0xFF, 0xE7,               # jmp r15
    ])
    
    # 附加病毒字符串数据
    shellcode.extend(virus_strings)
    shellcode.extend(infection_marker)
    
    return bytes(shellcode)


def create_infected_copy(source_path, output_path):
    """
    创建被感染的PE文件副本
    
    模拟感染型病毒的行为：
    1. 添加一个新的节区
    2. 修改入口点指向新节区
    3. 在新节区写入病毒代码（显示弹窗后跳回原始程序）
    """
    
    print(f"[*] 读取源文件: {source_path}")
    with open(source_path, 'rb') as f:
        data = bytearray(f.read())
    
    if len(data) < 64:
        print("[-] 文件太小，不是有效的PE文件")
        return False
    
    # 检查MZ头
    if data[0:2] != b'MZ':
        print("[-] 不是有效的PE文件 (缺少MZ头)")
        return False
    
    # 获取PE头偏移
    pe_offset = struct.unpack('<I', data[60:64])[0]
    print(f"[*] PE头偏移: 0x{pe_offset:08X}")
    
    if pe_offset + 24 >= len(data):
        print("[-] PE头偏移无效")
        return False
    
    # 检查PE签名
    if data[pe_offset:pe_offset+2] != b'PE':
        print("[-] 不是有效的PE文件 (缺少PE签名)")
        return False
    
    # 获取COFF头信息
    coff_header_offset = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff_header_offset+2:coff_header_offset+4])[0]
    optional_header_size = struct.unpack('<H', data[coff_header_offset+16:coff_header_offset+18])[0]
    
    print(f"[*] 当前节区数量: {num_sections}")
    
    # 获取可选头偏移和入口点
    optional_header_offset = coff_header_offset + 20
    
    # 判断是32位还是64位
    pe_type = struct.unpack('<H', data[optional_header_offset:optional_header_offset+2])[0]
    is_64bit = pe_type == 0x20B
    
    print(f"[*] 程序类型: {'64位' if is_64bit else '32位'}")
    
    # 获取映像基址
    if is_64bit:
        image_base = struct.unpack('<Q', data[optional_header_offset+24:optional_header_offset+32])[0]
    else:
        image_base = struct.unpack('<I', data[optional_header_offset+28:optional_header_offset+32])[0]
    
    print(f"[*] 映像基址: 0x{image_base:08X}")
    
    # 获取当前入口点（相对虚拟地址RVA）
    original_entry_point = struct.unpack('<I', data[optional_header_offset+16:optional_header_offset+20])[0]
    print(f"[*] 原始入口点(RVA): 0x{original_entry_point:08X}")
    
    # 节表偏移
    section_table_offset = optional_header_offset + optional_header_size
    
    # 读取最后一个节区的信息
    last_section_offset = section_table_offset + (num_sections - 1) * 40
    last_section_name = data[last_section_offset:last_section_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    last_section_virtual_size = struct.unpack('<I', data[last_section_offset+8:last_section_offset+12])[0]
    last_section_virtual_address = struct.unpack('<I', data[last_section_offset+12:last_section_offset+16])[0]
    last_section_raw_size = struct.unpack('<I', data[last_section_offset+16:last_section_offset+20])[0]
    last_section_raw_address = struct.unpack('<I', data[last_section_offset+20:last_section_offset+24])[0]
    
    print(f"[*] 最后一个节区: {last_section_name}")
    print(f"[*] 最后一个节区虚拟地址: 0x{last_section_virtual_address:08X}")
    print(f"[*] 最后一个节区原始地址: 0x{last_section_raw_address:08X}")
    
    # 计算新节区的信息
    section_alignment = 0x1000  # 通常的节区对齐
    file_alignment = 0x200      # 通常的文件对齐
    
    # 新节区的虚拟地址
    new_section_virtual_address = align_up(last_section_virtual_address + last_section_virtual_size, section_alignment)
    
    # 新节区的原始地址
    new_section_raw_address = align_up(last_section_raw_address + last_section_raw_size, file_alignment)
    
    # 生成病毒shellcode
    virus_code = create_virus_shellcode(original_entry_point, image_base)
    
    # 对齐病毒代码大小
    virus_code_size = align_up(len(virus_code), file_alignment)
    
    # 填充到对齐大小
    virus_code = virus_code + bytes(virus_code_size - len(virus_code))
    
    # 新节区的原始大小
    new_section_raw_size = virus_code_size
    
    # 新节区的虚拟大小（预留更多空间，使比例 > 5.0 以触发检测）
    new_section_virtual_size = virus_code_size * 6
    
    # 生成病毒节区名称
    new_section_name = generate_virus_section_name().encode('ascii')
    new_section_name = new_section_name.ljust(8, b'\x00')
    
    print(f"[*] 新节区名称: {new_section_name.rstrip(b'\\x00').decode()}")
    print(f"[*] 新节区虚拟地址: 0x{new_section_virtual_address:08X}")
    print(f"[*] 新节区原始地址: 0x{new_section_raw_address:08X}")
    print(f"[*] 病毒代码大小: {len(virus_code)} bytes")
    
    # 新节区的特征：可执行、可读、可写（RWE）
    # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    new_section_characteristics = 0x00000020 | 0x20000000 | 0x40000000 | 0x80000000
    
    # 创建新节区表项
    new_section_entry = bytearray(40)
    new_section_entry[0:8] = new_section_name
    struct.pack_into('<I', new_section_entry, 8, new_section_virtual_size)
    struct.pack_into('<I', new_section_entry, 12, new_section_virtual_address)
    struct.pack_into('<I', new_section_entry, 16, new_section_raw_size)
    struct.pack_into('<I', new_section_entry, 20, new_section_raw_address)
    struct.pack_into('<I', new_section_entry, 36, new_section_characteristics)
    
    # 更新节区数量
    new_num_sections = num_sections + 1
    struct.pack_into('<H', data, coff_header_offset + 2, new_num_sections)
    print(f"[*] 更新节区数量: {new_num_sections}")
    
    # 更新映像大小
    image_size_offset = optional_header_offset + 56  # SizeOfImage在可选头中的偏移
    new_image_size = align_up(new_section_virtual_address + new_section_virtual_size, section_alignment)
    struct.pack_into('<I', data, image_size_offset, new_image_size)
    print(f"[*] 更新映像大小: 0x{new_image_size:08X}")
    
    # 修改入口点指向新节区
    new_entry_point = new_section_virtual_address
    struct.pack_into('<I', data, optional_header_offset + 16, new_entry_point)
    print(f"[*] 修改入口点: 0x{original_entry_point:08X} (RVA) -> 0x{new_entry_point:08X} (RVA)")
    
    # 在节区表中添加新节区
    new_section_table_offset = section_table_offset + num_sections * 40
    data[new_section_table_offset:new_section_table_offset+40] = new_section_entry
    print(f"[*] 添加新节区到节区表偏移: 0x{new_section_table_offset:08X}")
    
    # 在文件末尾添加病毒代码
    # 首先填充到新的原始地址
    while len(data) < new_section_raw_address:
        data.append(0)
    
    # 添加病毒代码
    data.extend(virus_code)
    print(f"[*] 添加病毒代码到文件偏移: 0x{new_section_raw_address:08X}")
    
    # 保存被感染的文件
    print(f"[*] 保存被感染的文件: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print("[+] 感染完成!")
    print(f"    原始文件大小: {os.path.getsize(source_path)} bytes")
    print(f"    感染后大小: {len(data)} bytes")
    print(f"    增加大小: {len(data) - os.path.getsize(source_path)} bytes")
    print()
    print("[!] 病毒特征:")
    print("    1. 添加了可疑的病毒节区 (.virus)")
    print("    2. 劫持了程序入口点指向病毒代码")
    print("    3. 包含已知的病毒行为模式代码")
    print("    4. 包含病毒常用字符串 (CreateRemoteThread, VirtualAlloc等)")
    print("    5. 包含感染标记 [XIGUASecurity_Infected_Test_File]")
    print("    6. 病毒代码执行后会跳转回原始程序入口点")
    print()
    print("[!] 检测测试:")
    print("    - 此文件应能被主流杀毒软件识别为感染型病毒")
    print("    - 可用于测试杀毒软件的感染型病毒检测能力")
    
    return True


def main():
    print("=" * 60)
    print("感染型病毒模拟器 - 仅用于测试和教育目的")
    print("=" * 60)
    print()
    
    # 源文件路径（使用当前的主程序）
    source_path = r"C:\Users\MEMZ-UAC\Desktop\XIGUASecurity10x\antivirus-ui\src-tauri\target\debug\XIGUASecurity.exe"
    
    # 检查源文件是否存在
    if not os.path.exists(source_path):
        print(f"[-] 源文件不存在: {source_path}")
        print("[*] 请确保开发服务器已经编译完成")
        return
    
    # 生成输出文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = rf"C:\Users\MEMZ-UAC\Desktop\XIGUASecurity10x\tools\infected_test_{timestamp}.exe"
    
    print(f"[*] 源文件: {source_path}")
    print(f"[*] 输出文件: {output_path}")
    print()
    
    # 创建被感染的副本
    if create_infected_copy(source_path, output_path):
        print()
        print("=" * 60)
        print("测试建议:")
        print("=" * 60)
        print(f"1. 在杀毒软件中扫描此文件: {output_path}")
        print("2. 检查是否能检测到感染型病毒特征")
        print("3. 可以使用调试器运行此文件，观察病毒代码执行")
        print()
        print("警告: 此文件包含可执行的病毒代码，仅在隔离环境测试!")
    else:
        print("[-] 感染模拟失败")


if __name__ == "__main__":
    main()
