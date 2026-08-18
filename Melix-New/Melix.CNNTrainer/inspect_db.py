import sqlite3
conn = sqlite3.connect('Dataset.db')
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print('Tables:', [t[0] for t in tables])

for table in tables:
    table_name = table[0]
    print(f'\n=== Table: {table_name} ===')
    cursor.execute(f'PRAGMA table_info({table_name})')
    cols = cursor.fetchall()
    for col in cols:
        print(f'  {col[1]} ({col[2]})')

    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count = cursor.fetchone()[0]
    print(f'  Rows: {count}')

    cursor.execute(f'SELECT * FROM {table_name} LIMIT 3')
    rows = cursor.fetchall()
    for i, row in enumerate(rows):
        print(f'  Row {i}: len={len(row)}')
        for j, val in enumerate(row):
            if isinstance(val, bytes):
                print(f'    col[{j}] = bytes(len={len(val)})')
            else:
                print(f'    col[{j}] = {val} ({type(val).__name__})')

conn.close()
