# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import os
import json
import sqlite3
import hashlib
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import Dataset


from Augmentation import ByteAugmentation


class MelixFileDataset(Dataset):
    """从文件夹和SQLite数据库加载文件，提取12288原始字节
    支持通过 sample_index.json 秒级加载去重后的索引
    支持自动搜索文件夹下的所有 .db 文件"""

    def __init__(
        self,
        black_folder: str,
        white_folder: str,
        split: str = 'train',
        feature_dim: int = 12288,
        train_ratio: float = 0.8,
        seed: int = 42,
        augment: bool = False,
        index_path: str = 'sample_index.json'
    ):
        self.feature_dim = feature_dim
        self.augment = augment
        self.aug_transform = ByteAugmentation() if augment else None
        self._db_connections = {}  # 多个DB的连接缓存

        # 优先从预先生成的索引文件加载（秒开）
        if index_path and os.path.exists(index_path):
            black_files, white_files = self._load_from_index(index_path, split, train_ratio, seed)
        else:
            # 回退：实时扫描+去重（慢，仅首次生成索引时用）
            black_files, white_files = self._build_index(
                black_folder, white_folder, split, train_ratio, seed
            )

        self.samples = [(f, 1) for f in black_files] + [(f, 0) for f in white_files]

        print(f'  {split} set: {len(self.samples)} samples (augment={augment})')

    def _auto_find_dbs(self, folder: Path) -> list:
        """自动搜索文件夹下的所有 .db 文件"""
        if not folder.exists():
            return []
        db_files = []
        for item in folder.rglob('*.db'):
            if item.is_file():
                db_files.append(str(item))
        return db_files

    def _load_from_index(self, index_path: str, split: str, train_ratio: float, seed: int):
        """从 sample_index.json 秒级加载"""
        with open(index_path, 'r') as f:
            index = json.load(f)

        black_files = index.get('black_files', [])
        black_db_entries = index.get('black_db_entries', [])  # [(db_path, rowid), ...]
        white_files = index.get('white_files', [])
        white_db_entries = index.get('white_db_entries', [])

        # DB 样本转为内部标识: db://label|db_path|rowid
        black_ids = black_files + [f'db://b|{entry[0]}|{entry[1]}' for entry in black_db_entries]
        white_ids = white_files + [f'db://w|{entry[0]}|{entry[1]}' for entry in white_db_entries]

        np.random.seed(seed)
        np.random.shuffle(black_ids)
        np.random.shuffle(white_ids)

        b_split = int(len(black_ids) * train_ratio)
        w_split = int(len(white_ids) * train_ratio)

        if split == 'train':
            return black_ids[:b_split], white_ids[:w_split]
        else:
            return black_ids[b_split:], white_ids[w_split:]

    def _build_index(self, black_folder, white_folder, split, train_ratio, seed):
        """实时扫描并去重（首次生成索引时使用）"""
        import time

        print('  [Warning] sample_index.json not found, building index from scratch...')
        start = time.time()

        black_files = self._scan_files(Path(black_folder))
        white_files = self._scan_files(Path(white_folder))

        # 自动搜索所有 DB 文件
        black_db_files = self._auto_find_dbs(Path(black_folder))
        white_db_files = self._auto_find_dbs(Path(white_folder))

        print(f'  Found DBs: black={len(black_db_files)}, white={len(white_db_files)}')

        # 收集所有 DB 的 rowid
        black_db_entries = []
        for db_path in black_db_files:
            rowids = self._get_db_rowids(db_path)
            black_db_entries.extend([(db_path, rid) for rid in rowids])

        white_db_entries = []
        for db_path in white_db_files:
            rowids = self._get_db_rowids(db_path)
            white_db_entries.extend([(db_path, rid) for rid in rowids])

        print(f'  Raw: black={len(black_files)}(db={len(black_db_entries)}) white={len(white_files)}(db={len(white_db_entries)})')

        # 去重
        black_ids, black_db_unique = self._dedup_files_and_db(black_files, black_db_entries, is_black=True)
        white_ids, white_db_unique = self._dedup_files_and_db(white_files, white_db_entries, is_black=False)

        print(f'  After dedup: black={len(black_ids)} white={len(white_ids)}')
        print(f'  Index build time: {time.time()-start:.1f}s')

        # 保存索引供下次使用
        index = {
            'black_files': black_files,
            'black_db_entries': black_db_unique,
            'white_files': white_files,
            'white_db_entries': white_db_unique,
        }
        with open('sample_index.json', 'w') as f:
            json.dump(index, f)
        print('  Saved sample_index.json')

        np.random.seed(seed)
        np.random.shuffle(black_ids)
        np.random.shuffle(white_ids)

        b_split = int(len(black_ids) * train_ratio)
        w_split = int(len(white_ids) * train_ratio)

        if split == 'train':
            return black_ids[:b_split], white_ids[:w_split]
        else:
            return black_ids[b_split:], white_ids[w_split:]

    def _scan_files(self, folder: Path) -> list:
        if not folder.exists():
            return []
        return [str(p) for p in folder.rglob('*') if p.is_file() and not p.suffix == '.db']

    def _get_db_rowids(self, db_path: str) -> list:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT ROWID FROM Samples')
        rowids = [r[0] for r in c.fetchall()]
        conn.close()
        return rowids

    def _dedup_files_and_db(self, files, db_entries, is_black=True):
        """先处理文件夹样本，再处理DB样本，基于内容MD5去重"""
        seen = set()
        unique_files = []
        unique_db = []

        # 先处理文件夹样本（优先保留）
        for f in files:
            try:
                with open(f, 'rb') as fh:
                    data = fh.read(self.feature_dim)
            except Exception:
                data = b''
            h = self._md5_data(data)
            if h not in seen:
                seen.add(h)
                unique_files.append(f)

        # 再处理 DB 样本
        for db_path, rid in db_entries:
            data = self._get_db_data_once(db_path, rid)
            h = self._md5_data(data)
            if h not in seen:
                seen.add(h)
                unique_db.append((db_path, rid))

        # 构建标识符列表
        label = 'b' if is_black else 'w'
        ids = unique_files + [f'db://{label}|{entry[0]}|{entry[1]}' for entry in unique_db]

        return ids, unique_db

    @staticmethod
    def _md5_data(data, dim=12288):
        if len(data) < dim:
            data = data + bytes(dim - len(data))
        else:
            data = data[:dim]
        return hashlib.md5(data).hexdigest()

    def _get_db_data_once(self, db_path, rowid):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT Data FROM Samples WHERE ROWID = ?', (rowid,))
        row = c.fetchone()
        conn.close()
        return row[0] if row and row[0] else b''

    def _get_db_row(self, db_path: str, rowid: int) -> bytes:
        """获取指定 DB 的指定 rowid 数据，使用连接缓存"""
        if db_path not in self._db_connections:
            self._db_connections[db_path] = sqlite3.connect(db_path)
        conn = self._db_connections[db_path]
        cursor = conn.cursor()
        cursor.execute('SELECT Data FROM Samples WHERE ROWID = ?', (rowid,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
        return bytes(self.feature_dim)

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        file_path, label = self.samples[idx]

        if isinstance(file_path, str) and file_path.startswith('db://'):
            # 格式: db://label|db_path|rowid
            parts = file_path[5:].split('|')
            if len(parts) == 3:
                _, db_path, rowid = parts
                data = self._get_db_row(db_path, int(rowid))
            else:
                data = bytes(self.feature_dim)
        else:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(self.feature_dim)
            except Exception:
                data = bytes(self.feature_dim)

        if len(data) < self.feature_dim:
            data = data + bytes(self.feature_dim - len(data))
        else:
            data = data[:self.feature_dim]

        tensor = torch.from_numpy(np.frombuffer(data, dtype=np.uint8).copy()).long()

        if self.augment and self.aug_transform is not None:
            tensor = self.aug_transform(tensor)

        return tensor, label
