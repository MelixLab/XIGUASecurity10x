import sqlite3
import hashlib
import time

def inspect_db(path, label_name):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM Samples')
    count = cursor.fetchone()[0]
    print(f'{label_name}: {count} samples')

    # 快速算前100条的MD5看看速度
    start = time.time()
    cursor.execute('SELECT Data FROM Samples LIMIT 100')
    rows = cursor.fetchall()
    for row in rows:
        _ = hashlib.md5(row[0]).hexdigest()
    elapsed = time.time() - start
    print(f'  MD5 speed: {elapsed*10:.1f}s estimated for full DB')
    conn.close()
    return count

print('=== White DB ===')
w = inspect_db('WhiteData/Dataset.db', 'White')

print('\n=== Black DB ===')
b = inspect_db('blackData/Dataset.db', 'Black')

print(f'\nTotal DB samples: {w + b}')
