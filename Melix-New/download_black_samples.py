#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Malware Bazaar hourly feed 批量下载恶意样本到 D:\\Downloads\\Black"""

import os
import re
import shutil
import hashlib
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

# 配置
BASE_URL = "https://datalake.abuse.ch/malware-bazaar/hourly/"
DOWNLOAD_DIR = Path(r"D:\Downloads\Black")
PASSWORD = b"infected"
TEMP_DIR = Path(os.environ.get("TEMP", r"C:\Temp")) / "mbz_download"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

def fetch_html(url: str) -> str:
    """获取目录列表 HTML"""
    resp = requests.get(url, headers=HEADERS, timeout=30, verify=False)
    resp.raise_for_status()
    return resp.text

def list_zip_links(html: str) -> list[str]:
    """从 HTML 目录列表中提取 zip 文件链接"""
    links = re.findall(r'href="([^"]+\.zip)"', html)
    unique = []
    seen = set()
    for link in links:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique

def download_file(url: str, dest: Path) -> bool:
    """下载文件到指定路径（带进度条）"""
    try:
        with requests.get(url, headers=HEADERS, timeout=120, verify=False, stream=True) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length", 0))
            desc = dest.name[:40]
            with open(dest, "wb") as f, tqdm(
                desc=desc,
                total=total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                ncols=80,
                colour="green"
            ) as bar:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        bar.update(len(chunk))
        return True
    except Exception as e:
        print(f"[!] 下载失败 {url}: {e}")
        return False

def extract_zip(zip_path: Path, extract_to: Path) -> list[Path]:
    """解压 zip（带密码 infected）"""
    extracted = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.setpassword(PASSWORD)
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                zf.extract(member, extract_to)
                extracted.append(extract_to / member)
    except Exception as e:
        print(f"[!] 解压失败 {zip_path}: {e}")
    return extracted

def file_sha256(path: Path) -> str:
    """计算文件 SHA256"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] 获取目录列表: {BASE_URL}")
    try:
        html = fetch_html(BASE_URL)
    except Exception as e:
        print(f"[!] 无法获取目录列表: {e}")
        return

    zip_links = list_zip_links(html)
    print(f"[*] 发现 {len(zip_links)} 个 zip 文件")

    if not zip_links:
        print("[!] 没有找到 zip 文件，可能是页面结构变了")
        return

    # 只下载最近 1 个小时的 zip（网络慢，避免下太多）
    zip_links = zip_links[-1:]
    print(f"[*] 准备下载最近 {len(zip_links)} 个 zip")

    total_downloaded = 0
    total_skipped = 0

    for link in zip_links:
        zip_name = link.split("/")[-1]
        zip_url = f"{BASE_URL}{zip_name}"
        zip_path = TEMP_DIR / zip_name

        print(f"\n[*] 下载: {zip_name}")
        if not download_file(zip_url, zip_path):
            continue

        print(f"[*] 解压: {zip_name}")
        extract_dir = TEMP_DIR / zip_name.replace(".zip", "")
        extract_dir.mkdir(exist_ok=True)
        files = extract_zip(zip_path, extract_dir)
        print(f"[*] 解压出 {len(files)} 个文件")

        for f in tqdm(files, desc="移动样本", ncols=80, colour="blue"):
            try:
                sha = file_sha256(f)
                ext = f.suffix or ".bin"
                dest = DOWNLOAD_DIR / f"{sha}{ext}"
                if dest.exists():
                    total_skipped += 1
                else:
                    shutil.move(str(f), str(dest))
                    total_downloaded += 1
            except Exception as e:
                print(f"    [!] 处理失败 {f}: {e}")

        # 清理临时文件
        try:
            zip_path.unlink()
            shutil.rmtree(extract_dir)
        except:
            pass

    print(f"\n[*] 完成：下载 {total_downloaded} 个，跳过 {total_skipped} 个")
    print(f"[*] 保存位置: {DOWNLOAD_DIR}")

if __name__ == "__main__":
    # 禁用 SSL 警告
    requests.packages.urllib3.disable_warnings()
    main()
