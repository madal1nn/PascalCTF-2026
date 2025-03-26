#!/usr/bin/env python3

import os
import re
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "scripting.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 6004))

def last_index_of(lst, value):
    """Returns the last index of a value in a list, or -1 if not found."""
    for i in range(len(lst) - 1, -1, -1):
        if lst[i] == value:
            return i
    return -1

def solve_wires(colors, serial_digits):
    """Solve wires module based on Keep Talking and Nobody Explodes rules"""
    amount = len(colors)
    
    if amount == 3:
        if "Red" not in colors:
            return 2
        elif colors[-1] == "White":
            return 3
        elif colors.count("Blue") > 1:
            return last_index_of(colors, "Blue") + 1
        else:
            return 3
            
    elif amount == 4:
        if colors.count("Red") > 1 and serial_digits[-1] % 2 == 1:
            return last_index_of(colors, "Red") + 1
        elif colors[-1] == "Yellow" and "Red" not in colors:
            return 1
        elif colors.count("Blue") == 1:
            return 1
        elif colors.count("Yellow") > 1:
            return 4
        else:
            return 2

    elif amount == 5:
        if colors[-1] == "Black" and serial_digits[-1] % 2 == 1:
            return 4
        elif colors.count("Red") == 1 and colors.count("Yellow") > 1:
            return 1
        elif colors.count("Black") == 0:
            return 2
        else:
            return 1
            
    elif amount == 6:
        if colors.count("Yellow") == 0 and serial_digits[-1] % 2 == 1:
            return 3
        elif colors.count("Yellow") == 1 and colors.count("White") > 1:
            return 4
        elif colors.count("Red") == 0:
            return 6
        else:
            return 4

def solve_button(color, text, color_strip, battery_amount, label):
    """Solve button module"""
    def get_hold_digit(strip_color):
        if strip_color == "Blue":
            return 4
        elif strip_color == "White":
            return 1
        elif strip_color == "Yellow":
            return 5
        else:
            return 1
    
    if color == "Blue" and text == "Abort":
        return get_hold_digit(color_strip)
    elif battery_amount > 1 and text == "Detonate":
        return 0
    elif color == "White" and label == "CAR":
        return get_hold_digit(color_strip)
    elif battery_amount > 2 and label == "FRK":
        return 0
    elif color == "Yellow":
        return get_hold_digit(color_strip)
    elif color == "Red" and text == "Hold":
        return 0
    else:
        return get_hold_digit(color_strip)

def solve_keypads(symbols):
    """Solve keypads module"""
    symbol_sequences = [
        ['Ϙ', 'Ѧ', 'ƛ', 'Ϟ', 'Ѭ', 'ϗ', 'Ͽ'],
        ['Ӭ', 'Ϙ', 'Ͽ', 'Ҩ', '☆', 'ϗ', '¿'],
        ['©', 'Ѽ', 'Ҩ', 'Җ', 'Ԇ', 'ƛ', '☆'],
        ['б', '¶', 'ƀ', 'Ѭ', 'Җ', '¿', 'ټ'],
        ['ψ', 'ټ', 'ƀ', 'Ͼ', '¶', 'Ѯ', '★'],
        ['б', 'Ӭ', '҂', 'æ', 'ψ', 'Ҋ', 'Ω'],
    ]
    
    for sequence in symbol_sequences:
        if len(set(symbols) & set(sequence)) == 4:
            solution = []
            for symbol in sequence:
                if symbol in symbols:
                    solution.append(symbols.index(symbol) + 1)
            return solution
    return [1, 2, 3, 4]

def solve_complicated_wires(colors, leds, stars, serial_digits, battery_amount, ports):
    """Solve complicated wires module"""
    possibilities = ['C', 'S', 'S', 'C', 'S', 'P', 'C', 'P', 'S', 'D', 'D', 'D', 'B', 'P', 'B', 'B']
    
    sets = {
        'outside': {0},
        'Red': {1, 3, 4, 7, 8, 11, 12, 14},
        'Blue': {2, 4, 5, 7, 8, 10, 11, 13},
        'Star': {3, 6, 7, 10, 11, 13, 14, 15},
        'LED': {5, 8, 9, 11, 12, 13, 14, 15}
    }
    
    solution = {}
    for i in range(len(colors)):
        current = set()
        
        if colors[i] == "Red":
            current |= sets['Red'] - sets['Blue']
        elif colors[i] == "Blue":
            current |= sets['Blue'] - sets['Red']
        elif colors[i] == "Red and Blue":
            current |= sets['Red'] & sets['Blue']
        
        if leds[i]:
            if len(current) == 0:
                current |= sets['LED'] - sets['Blue'] - sets['Red']
            else:
                current &= sets['LED']
        else:
            current -= sets['LED']
        
        if stars[i]:
            if len(current) == 0:
                current |= sets['Star'] - sets['LED'] - sets['Blue'] - sets['Red']
            else:
                current &= sets['Star']
        else:
            current -= sets['Star']
        
        if len(current) == 0:
            current |= sets['outside']
        
        if len(current) == 1:
            solution[i + 1] = current.pop()
    
    output = []
    for i in range(len(colors)):
        wire_index = i + 1
        solution_value = solution[wire_index]
        if possibilities[solution_value] == 'C':
            output.append("cut")
        elif possibilities[solution_value] == 'S' and serial_digits[-1] % 2 == 0:
            output.append("cut")
        elif possibilities[solution_value] == 'P' and 'parallel' in ports:
            output.append("cut")
        elif possibilities[solution_value] == 'B' and battery_amount >= 2:
            output.append("cut")
        else:
            output.append("skip")
    
    return output

def main():
    io = remote(HOST, PORT)
    
    io.recvuntil(b"Modules to defuse:")
    modules_line = io.recvline().decode().strip()
    modules_count = int(modules_line)
    
    serial_line = io.recvline().decode()
    serial_match = re.search(r'Serial Number: (\d+)', serial_line)
    serial_digits = [int(d) for d in serial_match.group(1)] if serial_match else [0] * 6
    
    battery_line = io.recvline().decode()
    battery_match = re.search(r'Batteries: (\d+)', battery_line)
    battery_amount = int(battery_match.group(1)) if battery_match else 1
    
    label_line = io.recvline().decode()
    label_match = re.search(r'Label: (\w+)', label_line)
    label = label_match.group(1) if label_match else "NSA"
    
    ports_line = io.recvline().decode()
    ports_match = re.search(r'Ports: (.+)', ports_line)
    ports = ports_match.group(1).split(', ') if ports_match else []
    
    for module_num in range(1, modules_count + 1):        
        io.recvuntil(f"Select Module {module_num} to defuse (press Enter):".encode())
        io.sendline(b"")
        
        io.recvuntil(b"Module:")
        module_line = io.recvline().decode().strip()
        module_name = module_line.strip()
        
        io.recvuntil(b"Data:")
        data_line = io.recvline().decode().strip()
        
        data = eval(data_line)
        
        io.recvuntil(f"Enter your solution for {module_name}:".encode())
        
        if module_name == "Wires":
            colors = data['colors']
            solution = solve_wires(colors, serial_digits)
            io.recvuntil(b"Which wire to cut (enter wire number):")
            io.sendline(str(solution).encode())
            
        elif module_name == "Button":
            color = data['color']
            text = data['text']
            color_strip = data['color_strip']
            solution = solve_button(color, text, color_strip, battery_amount, label)
            
            io.recvuntil(b"Choose action (1 or 2):")
            if solution == 0:
                io.sendline(b"1")
            else:
                io.sendline(b"2")
                io.recvuntil(b"Release when timer shows digit (0-9):")
                io.sendline(str(solution).encode())
                
        elif module_name == "Keypads":
            symbols = data['symbols']
            solution = solve_keypads(symbols)
            io.recvuntil(b"Sequence (e.g., '1 3 2 4'):")
            io.sendline(' '.join(map(str, solution)).encode())
            
        elif module_name == "Complicated Wires":
            colors = data['colors']
            leds = data['leds']
            stars = data['stars']
            solution = solve_complicated_wires(colors, leds, stars, serial_digits, battery_amount, ports)
            
            for i, action in enumerate(solution):
                io.recvuntil(f"Wire {i+1}:".encode())
                io.sendline(action.encode())
        
        response = io.recvline().decode()
        if "Module defused successfully!" not in response:
            break
    
    victory_response = io.recvall(timeout=2).decode()
    if "CONGRATULATIONS" in victory_response:
        flag_match = re.search(r'(pascalCTF\{[^}]+\})', victory_response)
        if flag_match:
            flag = flag_match.group(1)
            print(flag)
    io.close()

if __name__ == "__main__":
    main()

