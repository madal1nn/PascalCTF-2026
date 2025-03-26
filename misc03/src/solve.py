#!/usr/bin/env python3
import sys
import argparse
from PIL import Image

def generate_border_coordinates(width, height):
    coords = []
    
    for x in range(width):
        coords.append((x, 0))
        
    for y in range(1, height-1):
        coords.append((width-1, y))
        
    if height > 1:
        for x in range(width-1, -1, -1):
            coords.append((x, height-1))

    if width > 1:
        for y in range(height-2, 0, -1):
            coords.append((0, y))
    return coords

def color_to_bit(color, threshold=128):
    r, g, b = color
    brightness = 0.299 * r + 0.587 * g + 0.114 * b
    return '0' if brightness < threshold else '1'

def extract_border_binary(image):
    width, height = image.size
    border_coords = generate_border_coordinates(width, height)
    binary_str = ""
    for coord in border_coords:
        pixel = image.getpixel(coord)
        bit = color_to_bit(pixel)
        binary_str += bit
        
    return binary_str

def find_repeating_pattern(binary_str):
    total_len = len(binary_str)

    for candidate_len in range(8, total_len + 1, 8):
        candidate = binary_str[:candidate_len]
        valid = True
        for i in range(total_len):
            if binary_str[i] != candidate[i % candidate_len]:
                valid = False
                break
        if valid:
            return candidate
    raise ValueError("Could not determine a valid repeating binary pattern in the border.")

def binary_to_text(binary_str):
    if len(binary_str) % 8 != 0:
        raise ValueError("The binary string length is not a multiple of 8.")
    text = ""
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        text += chr(int(byte, 2))
    return text

def retrieve_message(input_image_path):
    img = Image.open(input_image_path)
    img = img.convert("RGB")
    border_binary = extract_border_binary(img)
    
    original_binary = find_repeating_pattern(border_binary)
    message = binary_to_text(original_binary)
    return message

def main():
    parser = argparse.ArgumentParser(description="Retrieve the original message encoded in the binary frame of an image.")
    parser.add_argument("input_image", help="Path to the framed image file.")
    args = parser.parse_args()
    
    try:
        message = retrieve_message(args.input_image)
        print("Retrieved message:")
        print(message)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
