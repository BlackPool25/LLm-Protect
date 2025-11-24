"""
Create an image with embedded text for steganography testing.
"""

from PIL import Image, ImageDraw, ImageFont
import numpy as np

# Create an image with visible text
def create_image_with_text():
    """Create a simple image with visible text overlay."""
    img = Image.new('RGB', (400, 300), color='white')
    draw = ImageDraw.Draw(img)
    
    # Add some background pattern
    for i in range(0, 400, 20):
        draw.line([(i, 0), (i, 300)], fill='lightgray', width=1)
    for i in range(0, 300, 20):
        draw.line([(0, i), (400, i)], fill='lightgray', width=1)
    
    # Add visible text
    try:
        # Try to use a default font
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        # Fallback to default
        font = ImageFont.load_default()
    
    # Draw text
    text = "SECURITY TEST"
    draw.text((50, 120), text, fill='red', font=font)
    
    img.save('test_image_with_text.png', format='PNG')
    print("✓ Created test_image_with_text.png (visible text)")
    return img

# Create an image with LSB steganography simulation
def create_image_with_lsb_pattern():
    """Create an image with suspicious LSB patterns (simulated steganography)."""
    img = Image.new('RGB', (256, 256), color='blue')
    pixels = img.load()
    
    # Modify LSBs in a pattern (simulates hidden data)
    hidden_message = "SECRET_DATA_HIDDEN_HERE" * 100
    msg_idx = 0
    
    for y in range(256):
        for x in range(256):
            r, g, b = pixels[x, y]
            
            # Modify LSB of each channel based on hidden message
            if msg_idx < len(hidden_message):
                # Set LSB based on character
                char_val = ord(hidden_message[msg_idx]) % 2
                r = (r & 0xFE) | char_val  # Clear LSB and set new value
                
                msg_idx += 1
                if msg_idx < len(hidden_message):
                    char_val = ord(hidden_message[msg_idx]) % 2
                    g = (g & 0xFE) | char_val
                    msg_idx += 1
                
                if msg_idx < len(hidden_message):
                    char_val = ord(hidden_message[msg_idx]) % 2
                    b = (b & 0xFE) | char_val
                    msg_idx += 1
                
                pixels[x, y] = (r, g, b)
    
    img.save('test_image_lsb_stego.png', format='PNG')
    print("✓ Created test_image_lsb_stego.png (LSB pattern - simulated steganography)")
    return img

# Create a noisy image (high entropy)
def create_noisy_image():
    """Create an image with random noise (high entropy, suspicious)."""
    # Generate random noise
    noise = np.random.randint(0, 256, (200, 200, 3), dtype=np.uint8)
    img = Image.fromarray(noise, 'RGB')
    
    img.save('test_image_noise.png', format='PNG')
    print("✓ Created test_image_noise.png (random noise - high entropy)")
    return img

# Main
if __name__ == "__main__":
    print("Creating test images with embedded/suspicious patterns...\n")
    
    create_image_with_text()
    create_image_with_lsb_pattern()
    create_noisy_image()
    
    print("\n" + "="*60)
    print("Test images created successfully!")
    print("="*60)
    print("\nTest commands:")
    print("1. Visible text:")
    print("   python scripts/demo_guard.py --image test_image_with_text.png --text 'Check this'")
    print("\n2. LSB steganography pattern:")
    print("   python scripts/demo_guard.py --image test_image_lsb_stego.png --text 'Hidden data test' --debug")
    print("\n3. High entropy noise:")
    print("   python scripts/demo_guard.py --image test_image_noise.png --text 'Noise test'")
