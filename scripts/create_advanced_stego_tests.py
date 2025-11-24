"""
Create an image with hidden data simulating password and executable file signatures.
This tests advanced steganography detection capabilities.
"""

from PIL import Image
import numpy as np
import struct

def create_image_with_hidden_password():
    """
    Create an image with a hidden password embedded using LSB steganography.
    Simulates hiding sensitive text data.
    """
    # Create a normal-looking image (landscape photo simulation)
    img = Image.new('RGB', (400, 300), color='skyblue')
    pixels = img.load()
    
    # Add some visual content (gradient to make it look normal)
    for y in range(300):
        for x in range(400):
            r = 135 + int((x / 400) * 50)
            g = 206 + int((y / 300) * 30)
            b = 235 - int((x / 400) * 20)
            pixels[x, y] = (r, g, b)
    
    # Hidden password to embed
    hidden_password = "P@ssw0rd123!ADMIN_ACCESS_KEY_XYZ789"
    
    # Convert password to binary
    password_binary = ''.join(format(ord(char), '08b') for char in hidden_password)
    
    # Embed password in LSBs
    bit_index = 0
    for y in range(300):
        for x in range(400):
            if bit_index < len(password_binary):
                r, g, b = pixels[x, y]
                
                # Modify LSB of red channel
                if bit_index < len(password_binary):
                    r = (r & 0xFE) | int(password_binary[bit_index])
                    bit_index += 1
                
                # Modify LSB of green channel
                if bit_index < len(password_binary):
                    g = (g & 0xFE) | int(password_binary[bit_index])
                    bit_index += 1
                
                # Modify LSB of blue channel
                if bit_index < len(password_binary):
                    b = (b & 0xFE) | int(password_binary[bit_index])
                    bit_index += 1
                
                pixels[x, y] = (r, g, b)
            else:
                break
        if bit_index >= len(password_binary):
            break
    
    img.save('test_image_hidden_password.png', format='PNG')
    print(f"✓ Created test_image_hidden_password.png")
    print(f"  Hidden data: Password ({len(hidden_password)} chars)")
    print(f"  Binary bits embedded: {len(password_binary)}")
    return img

def create_image_with_exe_signature():
    """
    Create an image with hidden executable file signature (PE header simulation).
    This simulates hiding malicious executable data.
    """
    # Create a normal-looking image
    img = Image.new('RGB', (350, 250), color='lightgreen')
    pixels = img.load()
    
    # Add pattern to make it look like a photo
    for y in range(250):
        for x in range(350):
            r = 144 + int(np.sin(x/20) * 30)
            g = 238 + int(np.cos(y/20) * 15)
            b = 144 + int(np.sin((x+y)/30) * 20)
            pixels[x, y] = (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))
    
    # PE (Portable Executable) header signature
    # Real Windows EXE files start with "MZ" (0x4D5A) followed by PE header
    exe_signature = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
    exe_signature += b'PE\x00\x00L\x01\x03\x00'  # PE signature
    exe_signature += b'\x00\x00\x00\x00\x00\x00\x00\x00'
    
    # Add fake executable code
    fake_code = b'\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57'  # Common x86 assembly prologue
    exe_signature += fake_code
    
    # Convert to binary string
    exe_binary = ''.join(format(byte, '08b') for byte in exe_signature)
    
    # Embed in LSBs
    bit_index = 0
    for y in range(250):
        for x in range(350):
            if bit_index < len(exe_binary):
                r, g, b = pixels[x, y]
                
                # Embed in all three channels
                if bit_index < len(exe_binary):
                    r = (r & 0xFE) | int(exe_binary[bit_index])
                    bit_index += 1
                if bit_index < len(exe_binary):
                    g = (g & 0xFE) | int(exe_binary[bit_index])
                    bit_index += 1
                if bit_index < len(exe_binary):
                    b = (b & 0xFE) | int(exe_binary[bit_index])
                    bit_index += 1
                
                pixels[x, y] = (r, g, b)
            else:
                break
        if bit_index >= len(exe_binary):
            break
    
    img.save('test_image_hidden_exe.png', format='PNG')
    print(f"✓ Created test_image_hidden_exe.png")
    print(f"  Hidden data: PE executable signature ({len(exe_signature)} bytes)")
    print(f"  Binary bits embedded: {len(exe_binary)}")
    print(f"  Signature: MZ header + PE header + x86 code")
    return img

def create_image_with_combined_threats():
    """
    Create an image with multiple hidden threats:
    - Password
    - Executable signature
    - Encrypted data pattern
    """
    img = Image.new('RGB', (500, 400), color='coral')
    pixels = img.load()
    
    # Create realistic-looking gradient
    for y in range(400):
        for x in range(500):
            r = 255 - int((y / 400) * 50)
            g = 127 + int((x / 500) * 80)
            b = 80 + int(((x + y) / 900) * 100)
            pixels[x, y] = (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))
    
    # Combined hidden data
    hidden_data = "PASSWORD:admin123|EXE:MZ\x90\x00PE\x00\x00|ENCRYPTED:AES256_KEY_DATA"
    
    # Convert to binary
    data_binary = ''.join(format(ord(char) if isinstance(char, str) else char, '08b') 
                          for char in hidden_data)
    
    # Embed with high density (more suspicious)
    bit_index = 0
    for y in range(400):
        for x in range(500):
            if bit_index < len(data_binary):
                r, g, b = pixels[x, y]
                
                # Modify multiple bits per channel (more aggressive)
                if bit_index < len(data_binary):
                    r = (r & 0xFE) | int(data_binary[bit_index])
                    bit_index += 1
                if bit_index < len(data_binary):
                    g = (g & 0xFE) | int(data_binary[bit_index])
                    bit_index += 1
                if bit_index < len(data_binary):
                    b = (b & 0xFE) | int(data_binary[bit_index])
                    bit_index += 1
                
                pixels[x, y] = (r, g, b)
            else:
                break
        if bit_index >= len(data_binary):
            break
    
    img.save('test_image_combined_threats.png', format='PNG')
    print(f"✓ Created test_image_combined_threats.png")
    print(f"  Hidden data: Password + EXE signature + Encrypted data")
    print(f"  Total bits embedded: {len(data_binary)}")
    return img

# Main execution
if __name__ == "__main__":
    print("="*70)
    print("Creating Advanced Steganography Test Images")
    print("="*70)
    print()
    
    create_image_with_hidden_password()
    print()
    create_image_with_exe_signature()
    print()
    create_image_with_combined_threats()
    
    print()
    print("="*70)
    print("Test images created successfully!")
    print("="*70)
    print()
    print("Test commands:")
    print()
    print("1. Hidden Password:")
    print("   python scripts/demo_guard.py --image test_image_hidden_password.png --text 'Upload photo' --debug")
    print()
    print("2. Hidden EXE Signature:")
    print("   python scripts/demo_guard.py --image test_image_hidden_exe.png --text 'Profile picture' --debug")
    print()
    print("3. Combined Threats:")
    print("   python scripts/demo_guard.py --image test_image_combined_threats.png --text 'Check this' --debug")
    print()
    print("Expected: HIGH steganography scores (>0.7) indicating hidden data!")
