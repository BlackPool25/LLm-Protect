"""
Create a test image for guard system testing.
"""

from PIL import Image
import io

# Create a simple test image (red square)
img = Image.new('RGB', (200, 200), color='red')
img.save('test_image.png', format='PNG')
print("Created test_image.png (200x200 red square)")

# Create a more complex test image (gradient)
gradient = Image.new('RGB', (300, 300))
pixels = gradient.load()
for y in range(300):
    for x in range(300):
        r = int((x / 300) * 255)
        g = int((y / 300) * 255)
        b = 128
        pixels[x, y] = (r, g, b)
gradient.save('test_gradient.png', format='PNG')
print("Created test_gradient.png (300x300 gradient)")

print("\nTest images created successfully!")
print("Run: python scripts/demo_guard.py --image test_image.png --text 'Check this image'")
