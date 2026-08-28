import struct
import zlib
import os
from struct import pack

def create_ico_from_png(png_path, ico_path):
    """Create an ICO file from a PNG image."""
    with open(png_path, 'rb') as f:
        png_data = f.read()

    # Get PNG dimensions from IHDR
    width = png_data[16]
    height = png_data[20]

    # ICO format: header + 1 entry + PNG data
    # ICO header: reserved(2) + type(2) + count(2)
    header = pack('<HHH', 0, 1, 1)

    # ICO entry: width(1) + height(1) + colors(1) + reserved(1) + planes(2) + bpp(2) + size(4) + offset(4)
    entry = pack('<BBBBHHII', 
        width if width < 256 else 0,
        height if height < 256 else 0,
        0,  # colors
        0,  # reserved
        1,  # planes
        32, # bpp
        len(png_data),
        22  # offset (6 header + 16 entry)
    )

    with open(ico_path, 'wb') as f:
        f.write(header + entry + png_data)

# Convert 32x32 PNG to ICO
png_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src-tauri', 'icons', '32x32.png')
ico_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src-tauri', 'icons', 'icon.ico')
create_ico_from_png(png_path, ico_path)
print(f'Created icon.ico from {png_path}')