import os
import sqlite3
import hashlib
import json
import time
from pathlib import Path

def scan_files(folder):
    if not Path(folder).exists():
        return []
    return [str(p) for p in Path(folder).rglob('*') if p.is_file()]

def get_db_rowids(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT ROWID FROM Samples')
    rowids = [r[0] for r in c.fetchall()]
    conn.close()
    return rowids

def get_db_data(db_path, rowid):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT Data FROM Samples WHERE ROWID = ?', (rowid,))
    row = c.fetchone()
    conn.close()
    return row[0] if row and row[0] else b''

def md5_data(data, dim=12288):
    if len(data) < dim:
        data = data + bytes(dim - len(data))
    else:
        data = data[:dim]
    return hashlib.md5(data).hexdigest()

def process_set(name, folder, db_path):
    files = scan_files(folder)
    db_rowids = get_db_rowids(db_path) if db_path and os.path.exists(db_path) else []

    seen = set()
    unique_files = []
    unique_db = []

    print(f'\n=== {name} ===')
    print(f'  Folder: {len(files)} files')
    print(f'  DB: {len(db_rowids)} rows')

    # 先处理文件夹（优先保留）
    for f in files:
        try:
            with open(f, 'rb') as fh:
                data = fh.read(12288)
        except:
            data = b''
        h = md5_data(data)
        if h not in seen:
            seen.add(h)
            unique_files.append(f)

    # 再处理 DB
    dup_in_db = 0
    for rid in db_rowids:
        data = get_db_data(db_path, rid)
        h = md5_data(data)
        if h not in seen:
            seen.add(h)
            unique_db.append(rid)
        else:
            dup_in_db += 1

    print(f'  After dedup: folder={len(unique_files)} db={len(unique_db)}')
    print(f'  Removed from DB: {dup_in_db}')
    return unique_files, unique_db

start = time.time()
white_files, white_db = process_set('White', r'D:\Downloads\White', 'WhiteData/Dataset.db')
black_files, black_db = process_set('Black', r'D:\Downloads\Black', 'blackData/Dataset.db')

# 计算训练/验证分割（80/20）
train_ratio = 0.8
w_train = int(len(white_files) * train_ratio) + int(len(white_db) * train_ratio)
b_train = int(len(black_files) * train_ratio) + int(len(black_db) * train_ratio)
w_val = len(white_files) + len(white_db) - w_train
b_val = len(black_files) + len(black_db) - b_train

print(f'\n=== FINAL STATS ===')
print(f'White total: {len(white_files) + len(white_db)} (train~{w_train}, val~{w_val})')
print(f'Black total: {len(black_files) + len(black_db)} (train~{b_train}, val~{b_val})')
print(f'Total unique: {len(white_files)+len(white_db)+len(black_files)+len(black_db)}')
print(f'Black/White ratio: {len(black_files)+len(black_db)}/{len(white_files)+len(white_db)} = {(len(black_files)+len(black_db))/(len(white_files)+len(white_db)):.2f}:1')
print(f'Time: {time.time()-start:.1f}s')

# 保存去重索引，供 DataLoader 直接使用
index = {
    'white_files': white_files,
    'white_db': white_db,
    'black_files': black_files,
    'black_db': black_db,
    'white_db_path': 'WhiteData/Dataset.db',
    'black_db_path': 'blackData/Dataset.db',
}
with open('sample_index.json', 'w') as f:
    json.dump(index, f)
print('\nSaved sample_index.json')
