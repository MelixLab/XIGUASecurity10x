#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV 哈希数据转换工具
将其他平台导出的 CSV 文件转换为 XIGUA Security 平台的哈希库格式

使用方法:
    python csv_to_hashdb.py input.csv output.txt --malicious-family "Trojan.Generic"
    
CSV 文件格式支持:
    - 包含 hash, md5, sha256, sha1 等列名（自动识别）
    - 包含 type, result, is_virus, malicious 等列名（自动识别是否恶意）
"""

import csv
import sys
import argparse
import os
from typing import List, Dict, Optional


def detect_hash_column(headers: List[str]) -> Optional[str]:
    """自动检测哈希列名"""
    hash_columns = ['hash', 'md5', 'sha256', 'sha1', 'sha512', 'file_hash', 'hash_value', 'sha-256', 'sha-1', 'sha-512']
    headers_lower = [h.lower() for h in headers]
    for col in hash_columns:
        if col.lower() in headers_lower:
            # 返回原始列名（保持大小写）
            idx = headers_lower.index(col.lower())
            return headers[idx]
    return None


def detect_type_column(headers: List[str]) -> Optional[str]:
    """自动检测类型/结果列名"""
    type_columns = ['type', 'result', 'is_virus', 'malicious', 'is_malicious', 'category', 'status', 'verdict', '状态']
    headers_lower = [h.lower() for h in headers]
    for col in type_columns:
        if col.lower() in headers_lower:
            idx = headers_lower.index(col.lower())
            return headers[idx]
    return None


def detect_family_column(headers: List[str]) -> Optional[str]:
    """自动检测病毒家族列名"""
    family_columns = ['family', 'virus_family', 'malware_family', 'threat_name', 'virus_name', 'malware_name', 'classification']
    for col in family_columns:
        if col.lower() in [h.lower() for h in headers]:
            return col
    return None


def is_malicious_value(value: str) -> bool:
    """判断是否为恶意文件标记"""
    if not value:
        return False
    value_lower = str(value).lower().strip()
    malicious_keywords = [
        'virus', 'malware', 'trojan', 'worm', 'backdoor', 'ransomware',
        'spyware', 'adware', 'rootkit', 'keylogger', 'botnet',
        'malicious', 'infected', 'threat', 'dangerous', 'suspicious',
        'true', '1', 'yes', 'y', 'positive', 'detected', 'bad',
        'black', 'blacklist', 'blocked', 'quarantine'
    ]
    return any(keyword in value_lower for keyword in malicious_keywords)


def normalize_hash(hash_value: str) -> Optional[str]:
    """标准化哈希值"""
    if not hash_value:
        return None
    # 移除空格和特殊字符
    hash_clean = hash_value.strip().lower()
    # 只保留十六进制字符
    hash_clean = ''.join(c for c in hash_clean if c in '0123456789abcdef')
    # 验证长度（MD5=32, SHA1=40, SHA256=64）
    if len(hash_clean) not in [32, 40, 64]:
        return None
    return hash_clean


def convert_csv_to_hashdb(
    input_file: str,
    output_file: str,
    malicious_family: str = "Trojan.Generic",
    whitelist_family: str = "",
    delimiter: str = ",",
    encoding: str = "utf-8"
):
    """
    将 CSV 文件转换为 XIGUA Security 云端哈希平台格式
    
    输出格式（TXT）:
    hash,is_virus,virus_family
    
    例如:
    d41d8cd98f00b204e9800998ecf8427e,1,Trojan.Generic
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,0,
    
    说明:
    - is_virus: 0=白名单, 1=黑名单(病毒), 2=可疑
    - virus_family: 病毒家族名称，白名单可为空
    """
    
    print(f"[*] 读取 CSV 文件: {input_file}")
    
    if not os.path.exists(input_file):
        print(f"[ERROR] 文件不存在: {input_file}")
        return False
    
    # 统计信息
    stats = {
        'total': 0,
        'malicious': 0,
        'whitelist': 0,
        'skipped': 0,
        'families': {}
    }
    
    # 读取 CSV
    try:
        with open(input_file, 'r', encoding=encoding, errors='ignore') as f:
            # 尝试检测分隔符
            sample = f.read(4096)
            f.seek(0)
            
            # 使用 csv.Sniffer 自动检测分隔符
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
                delimiter = dialect.delimiter
                print(f"[*] 自动检测到分隔符: '{delimiter}'")
            except:
                print(f"[*] 使用默认分隔符: '{delimiter}'")
            
            reader = csv.DictReader(f, delimiter=delimiter)
            headers = reader.fieldnames
            
            if not headers:
                print("[ERROR] 无法读取 CSV 表头")
                return False
            
            print(f"[*] CSV 列名: {headers}")
            
            # 自动检测列
            hash_col = detect_hash_column(headers)
            type_col = detect_type_column(headers)
            family_col = detect_family_column(headers)
            
            if not hash_col:
                print("[ERROR] 无法识别哈希列，请检查 CSV 格式")
                print(f"    支持的列名: hash, md5, sha256, sha1, file_hash, hash_value")
                return False
            
            print(f"[*] 哈希列: {hash_col}")
            if type_col:
                print(f"[*] 类型列: {type_col}")
            if family_col:
                print(f"[*] 家族列: {family_col}")
            
            # 处理数据
            entries = []
            
            for row in reader:
                stats['total'] += 1
                
                # 获取哈希值
                hash_value = row.get(hash_col, '').strip()
                hash_normalized = normalize_hash(hash_value)
                
                if not hash_normalized:
                    stats['skipped'] += 1
                    continue
                
                # 判断是否为恶意文件
                is_virus = False
                virus_family = ""
                
                if type_col:
                    type_value = row.get(type_col, '').strip()
                    is_virus = is_malicious_value(type_value)
                
                # 获取病毒家族
                if family_col:
                    virus_family = row.get(family_col, '').strip()
                
                # 如果没有家族信息，使用默认值
                if is_virus:
                    if not virus_family:
                        virus_family = malicious_family
                    stats['malicious'] += 1
                else:
                    if whitelist_family:
                        virus_family = whitelist_family
                    stats['whitelist'] += 1
                
                # 统计家族分布
                if virus_family:
                    stats['families'][virus_family] = stats['families'].get(virus_family, 0) + 1
                
                # 构建输出行
                # 格式: hash,is_virus,virus_family
                is_virus_flag = "1" if is_virus else "0"
                entries.append(f"{hash_normalized},{is_virus_flag},{virus_family}")
                
    except Exception as e:
        print(f"[ERROR] 读取 CSV 失败: {e}")
        return False
    
    # 写入输出文件
    print(f"\n[*] 写入哈希库文件: {output_file}")
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入文件头注释
            f.write(f"# XIGUA Security Hash Database\n")
            f.write(f"# Source: {os.path.basename(input_file)}\n")
            f.write(f"# Total entries: {len(entries)}\n")
            f.write(f"# Malicious: {stats['malicious']}\n")
            f.write(f"# Whitelist: {stats['whitelist']}\n")
            f.write(f"# Format: hash,is_virus,virus_family\n")
            f.write(f"# is_virus: 0=whitelist, 1=virus, 2=suspicious\n")
            f.write(f"#\n")
            
            # 写入数据
            for entry in entries:
                f.write(entry + "\n")
                
    except Exception as e:
        print(f"[ERROR] 写入文件失败: {e}")
        return False
    
    # 打印统计信息
    print(f"\n[+] 转换完成!")
    print(f"    总记录数: {stats['total']}")
    print(f"    恶意文件: {stats['malicious']}")
    print(f"    白名单文件: {stats['whitelist']}")
    print(f"    跳过(无效哈希): {stats['skipped']}")
    print(f"    输出条目: {len(entries)}")
    
    if stats['families']:
        print(f"\n[*] 病毒家族分布:")
        # 按数量排序
        sorted_families = sorted(stats['families'].items(), key=lambda x: x[1], reverse=True)
        for family, count in sorted_families[:10]:  # 只显示前10个
            print(f"    {family}: {count}")
        if len(sorted_families) > 10:
            print(f"    ... 还有 {len(sorted_families) - 10} 个家族")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='将 CSV 格式的哈希数据转换为 XIGUA Security 哈希库格式',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法
  python csv_to_hashdb.py virusmark-export.csv hashdb.txt
  
  # 指定恶意文件家族
  python csv_to_hashdb.py input.csv output.txt --malicious-family "Ransomware.WannaCry"
  
  # 指定白名单家族
  python csv_to_hashdb.py input.csv output.txt --whitelist-family "Trusted.Software"
  
  # 指定分隔符和编码
  python csv_to_hashdb.py input.csv output.txt --delimiter ";" --encoding "gbk"
        """
    )
    
    parser.add_argument('input', help='输入 CSV 文件路径')
    parser.add_argument('output', help='输出哈希库文件路径')
    parser.add_argument('--malicious-family', default='Trojan.Generic',
                        help='恶意文件的默认病毒家族 (默认: Trojan.Generic)')
    parser.add_argument('--whitelist-family', default='',
                        help='白名单文件的家族标记 (默认: 空)')
    parser.add_argument('--delimiter', default=',',
                        help='CSV 分隔符 (默认: 逗号)')
    parser.add_argument('--encoding', default='utf-8',
                        help='文件编码 (默认: utf-8)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("XIGUA Security - CSV 哈希数据转换工具")
    print("=" * 60)
    print()
    
    success = convert_csv_to_hashdb(
        input_file=args.input,
        output_file=args.output,
        malicious_family=args.malicious_family,
        whitelist_family=args.whitelist_family,
        delimiter=args.delimiter,
        encoding=args.encoding
    )
    
    if success:
        print("\n[+] 转换成功!")
        return 0
    else:
        print("\n[-] 转换失败!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
