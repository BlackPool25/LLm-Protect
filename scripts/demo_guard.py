"""
Demo CLI for the Image + Emoji Security Guard System.

Usage:
    python scripts/demo_guard.py --text "Hello world! 😀"
    python scripts/demo_guard.py --image test.png --text "Check this image"
    python scripts/demo_guard.py --text "⚔️🔫💣 Attack!"
    python scripts/demo_guard.py --text "Test" --debug
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from security import guard_request, IncomingRequest


def load_image(image_path: str) -> bytes:
    """Load image file as bytes."""
    with open(image_path, 'rb') as f:
        return f.read()


def main():
    parser = argparse.ArgumentParser(
        description="Demo CLI for Image + Emoji Security Guard System"
    )
    parser.add_argument(
        "--text",
        type=str,
        help="Text input to analyze"
    )
    parser.add_argument(
        "--image",
        type=str,
        help="Path to image file to analyze"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.text and not args.image:
        print("Error: Must provide --text and/or --image")
        parser.print_help()
        sys.exit(1)
    
    # Load image if provided
    image_bytes = None
    if args.image:
        try:
            image_bytes = load_image(args.image)
            print(f"✓ Loaded image: {args.image} ({len(image_bytes)} bytes)")
        except Exception as e:
            print(f"✗ Failed to load image: {e}")
            sys.exit(1)
    
    # Create request
    request = IncomingRequest(
        text=args.text,
        image_bytes=image_bytes,
        metadata={
            "source": "demo_cli",
            "user_id": "demo_user"
        }
    )
    
    print("\n" + "="*60)
    print("SECURITY GUARD ANALYSIS")
    print("="*60)
    
    if args.text:
        print(f"Text: {args.text[:100]}{'...' if len(args.text) > 100 else ''}")
    if args.image:
        print(f"Image: {args.image}")
    
    print("\nAnalyzing...\n")
    
    # Run guard
    try:
        result = guard_request(request, debug=args.debug)
        
        # Display result
        print("="*60)
        print("RESULT")
        print("="*60)
        print(f"Action:        {result.action.value.upper()}")
        print(f"Anomaly Score: {result.anomaly_score:.3f}")
        
        if result.reasons:
            print(f"\nReasons:")
            for reason in result.reasons:
                print(f"  • {reason}")
        
        if result.message:
            print(f"\nMessage to User:")
            print(f"  {result.message}")
        
        if result.action.value == "allow" and result.sanitized_text:
            print(f"\nSanitized Text:")
            print(f"  {result.sanitized_text[:200]}{'...' if len(result.sanitized_text) > 200 else ''}")
        
        # Debug output
        if args.debug and result.debug:
            print("\n" + "="*60)
            print("DEBUG INFORMATION")
            print("="*60)
            
            # Pretty print debug info
            debug_json = json.dumps(result.debug, indent=2, default=str)
            print(debug_json)
        
        print("\n" + "="*60)
        
        # Exit code based on action
        if result.action.value == "allow":
            sys.exit(0)
        elif result.action.value == "rewrite":
            sys.exit(2)
        else:  # block
            sys.exit(1)
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
