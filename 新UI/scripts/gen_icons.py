import struct
import zlib
import os

def create_png(width, height, r, g, b, filepath):
    """Create a simple solid-color PNG file."""
    # RGBA pixel data
    raw_data = b''
    for y in range(height):
        raw_data += b'\x00'  # filter byte
        for x in range(width):
            # Create a shield shape
            cx, cy = width // 2, height // 2
            dx = abs(x - cx) / (width / 2)
            dy = abs(y - cy) / (height / 2)
            # Simple shield shape approximation
            in_shield = (
                dy < 0.9 and dx < 0.8 - dy * 0.3
            ) or (
                y > cy and dy < 0.95 and dx < 0.7 - (dy - 0.5) * 0.2
            )
            if in_shield:
                raw_data += struct.pack('BBBB', r, g, b, 255)
            else:
                raw_data += struct.pack('BBBB', 0, 0, 0, 0)

    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)
        return struct.pack('>I', len(data)) + chunk + crc

    # PNG signature
    signature = b'\x89PNG\r\n\x1a\n'
    # IHDR chunk
    ihdr = make_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    # IDAT chunk
    compressed = zlib.compress(raw_data)
    idat = make_chunk(b'IDAT', compressed)
    # IEND chunk
    iend = make_chunk(b'IEND', b'')

    with open(filepath, 'wb') as f:
        f.write(signature + ihdr + idat + iend)

# Generate icons
icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src-tauri', 'icons')
os.makedirs(icons_dir, exist_ok=True)

# Primary color: #00BFA5
r, g, b = 0, 191, 165

sizes = {
    '32x32.png': 32,
    '128x128.png': 128,
    '128x128@2x.png': 256,
}

for name, size in sizes.items():
    create_png(size, size, r, g, b, os.path.join(icons_dir, name))
    print(f'Created {name} ({size}x{size})')

# Create icon.ico (simple - just copy the 32x32 for now, real ICO would need multi-res)
# For simplicity, we'll just note that icon.ico is needed
# Tauri does support PNG icons for Windows too

print('Icons generated successfully!')