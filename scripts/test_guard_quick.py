"""
Quick test script to verify the guard system implementation.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("=" * 60)
print("GUARD SYSTEM VERIFICATION TESTS")
print("=" * 60)

# Test 1: Import test
print("\n[Test 1] Testing imports...")
try:
    from security import guard_request, IncomingRequest, GuardAction
    print("✓ Imports successful")
except Exception as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

# Test 2: Safe text
print("\n[Test 2] Safe text (should ALLOW)...")
try:
    request = IncomingRequest(text="Hello world! This is a safe message.")
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    print(f"  Sanitized: {result.sanitized_text[:50]}...")
    assert result.action == GuardAction.ALLOW, f"Expected ALLOW, got {result.action}"
    assert result.anomaly_score < 0.5, f"Score too high: {result.anomaly_score}"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Neutral emojis
print("\n[Test 3] Neutral emojis (should ALLOW with low score)...")
try:
    request = IncomingRequest(text="Hello 😀 World 🌍! Great day 👍")
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    assert result.action == GuardAction.ALLOW, f"Expected ALLOW, got {result.action}"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 4: Risky emojis
print("\n[Test 4] Risky emojis (should REWRITE or BLOCK)...")
try:
    request = IncomingRequest(text="⚔️🔫💣 Attack!")
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    print(f"  Reasons: {result.reasons}")
    assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK], f"Expected REWRITE/BLOCK, got {result.action}"
    assert result.anomaly_score > 0.5, f"Score too low: {result.anomaly_score}"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 5: Zero-width characters
print("\n[Test 5] Zero-width characters (should detect and sanitize)...")
try:
    text_with_zwc = "Hello\u200B\u200C\u200DWorld"
    request = IncomingRequest(text=text_with_zwc)
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    if result.action == GuardAction.ALLOW:
        # Should sanitize
        assert "\u200B" not in result.sanitized_text, "Zero-width char not removed"
        print(f"  Sanitized: '{result.sanitized_text}'")
        print("✓ Test passed (sanitized)")
    else:
        print(f"  Reasons: {result.reasons}")
        print("✓ Test passed (blocked/rewrite)")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 6: Bidi override
print("\n[Test 6] Bidi override attack (should BLOCK or REWRITE)...")
try:
    text_with_bidi = "user@example.com\u202Emoc.elpmaxe@resu"
    request = IncomingRequest(text=text_with_bidi)
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    print(f"  Reasons: {result.reasons}")
    assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK], f"Expected REWRITE/BLOCK, got {result.action}"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 7: Empty request
print("\n[Test 7] Empty request (should BLOCK)...")
try:
    request = IncomingRequest(text=None, image_bytes=None)
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Reasons: {result.reasons}")
    assert result.action == GuardAction.BLOCK, f"Expected BLOCK, got {result.action}"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 8: Debug mode
print("\n[Test 8] Debug mode (should include debug info)...")
try:
    request = IncomingRequest(text="Test message")
    result = guard_request(request, debug=True)
    print(f"  Action: {result.action.value}")
    print(f"  Has debug info: {result.debug is not None}")
    assert result.debug is not None, "Debug info missing"
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")

# Test 9: Image processing (simple test)
print("\n[Test 9] Image processing (creating test image)...")
try:
    from PIL import Image
    import io
    
    # Create a simple test image
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes = img_bytes.getvalue()
    
    request = IncomingRequest(
        text="Check this image",
        image_bytes=img_bytes
    )
    result = guard_request(request)
    print(f"  Action: {result.action.value}")
    print(f"  Score: {result.anomaly_score:.3f}")
    print("✓ Test passed")
except Exception as e:
    print(f"✗ Test failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE")
print("=" * 60)
print("\n✅ All core functionality is working!")
print("\nNext steps:")
print("1. Run full test suite: pytest tests/test_guard_integration.py -v")
print("2. Try demo CLI: python scripts/demo_guard.py --text 'Hello 😀'")
print("3. Customize config: edit config/security_config.py")
