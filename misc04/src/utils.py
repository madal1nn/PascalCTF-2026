import random
from colorama import Fore, Style

def last_index_of(list: list, value) -> int:
    """Returns the last index of a value in a list, or -1 if not found."""
    for i in range(len(list) - 1, -1, -1):
        if list[i] == value:
            return i
    return -1

class bomb:
    def __init__(self, modules: int):
        self.module_number = modules
        self.serial_digits = [random.randint(0, 9) for _ in range(6)]
        self.battery_amount = random.randint(1, 3)
        self.label = random.choice(["CAR", "FRK", "CLR", "SND", "SIG", "IND", "NSA"])
        self.ports = random.choices(["parallel", "serial", "ps2", "usb"], k=random.randint(1, 3))
        self.modules = [module(i, self) for i in module.get_random_modules(modules)]
    
    def print_bomb(self):
        for module in self.modules:
            print(f"Module: {module.name}")
            print(module.get_art_from_name(module.name, module.data))
            print("Data:", module.data)
            print("Solution:", module.solution)
            print("Actions:", module.actions)
            print("\n")

class module:
    def __init__(self, module_name: str, bomb: bomb):
        self.name = module_name
        self.bomb = bomb
        self.data = self.get_data_from_name(module_name)
        self.solution = self.get_solution(module_name, self.data, bomb)
        self.actions = self.get_actions(module_name)

    @staticmethod
    def modules():
        return [
            "Wires",
            "Button",
            "Keypads",
            "Complicated Wires",
        ]
    
    @staticmethod
    def get_data_from_name(module_name: str) -> dict:
        if module_name == "Wires":
            return module.get_wire_data()
        elif module_name == "Button":
            return module.get_button_data()
        elif module_name == "Keypads":
            return module.get_keypad_data()
        elif module_name == "Complicated Wires":
            return module.get_Complicated_Wires_data()
        else:
            raise ValueError(f"Unknown module name: {module_name}")
    
    @staticmethod
    def get_solution(module_name: str, module_data: dict, bomb: bomb) -> dict | list:
        if module_name == "Wires":
            return module.get_wires_solution(module_data, bomb)
        elif module_name == "Button":
            return module.get_button_solution(module_data, bomb)
        elif module_name == "Keypads":
            return module.get_keypad_solution(module_data)
        elif module_name == "Complicated Wires":
            return module.get_Complicated_Wires_solution(module_data, bomb)
        else:
            raise ValueError(f"Unknown module name: {module_name}")
    
    @staticmethod
    def get_art_from_name(module_name: str, module_data: dict) -> str:
        art = "___________"
        if module_name == "Wires":
            for i in range(module_data["amount"]):
                color = module_data["colors"][i]
                art += "\n| "
                if color == "Red":
                    art += Fore.RED + "═══════" + Style.RESET_ALL
                elif color == "Blue":
                    art += Fore.CYAN + "═══════" + Style.RESET_ALL
                elif color == "White":
                    art += Fore.WHITE + "═══════" + Style.RESET_ALL
                elif color == "Yellow":
                    art += Fore.YELLOW + "═══════" + Style.RESET_ALL
                elif color == "Black":
                    art += Fore.BLACK + "═══════" + Style.RESET_ALL
                
                art += " |"
            
            for i in range(6 - module_data["amount"]):
                art += "\n|         |"
            art += "\n"
            
        elif module_name == "Button":
            art += \
"""
|   ___   |
|  /   \\  |
| | ### | |
|  \\___/  |
|         |
|         |
"""
            art += "|  "
            if module_data["color_strip"] == "Red":
                art += Fore.RED + "═════" + Style.RESET_ALL
            elif module_data["color_strip"] == "Blue":
                art += Fore.CYAN + "═════" + Style.RESET_ALL
            elif module_data["color_strip"] == "White":
                art += Fore.WHITE + "═════" + Style.RESET_ALL
            elif module_data["color_strip"] == "Yellow":
                art += Fore.YELLOW + "═════" + Style.RESET_ALL
            elif module_data["color_strip"] == "Pink":
                art += Fore.MAGENTA + "═════" + Style.RESET_ALL
            elif module_data["color_strip"] == "Green":
                art += Fore.GREEN + "═════" + Style.RESET_ALL
            art += "  |\n"
        
        elif module_name == "Keypads":
            symbols = module_data["symbols"]
            art += \
f"""
| ___ ___ |
| |{symbols[0]}| |{symbols[1]}| |
| |_| |_| |
|         |
| ___ ___ |
| |{symbols[2]}| |{symbols[3]}| | 
| |_| |_| |
"""
        if module_name == "Complicated Wires":
            art += "\n"
            for i in range(module_data["amount"]):
                color = module_data["colors"][i]
                led = "•" if module_data["leds"][i] else "◦"
                star = "★" if module_data["stars"][i] else "☆"
                art += f"|{led}"
                if color == "Red":
                    art += Fore.RED + "═══════" + Style.RESET_ALL
                elif color == "Blue":
                    art += Fore.CYAN + "═══════" + Style.RESET_ALL
                elif color == "Red and Blue":
                    art += Fore.RED + "═══" + Fore.WHITE + "═" + Fore.CYAN + "═══" + Style.RESET_ALL
                elif color == "White":
                    art += Fore.WHITE + "═══════" + Style.RESET_ALL 
                art += f"{star}|\n"
            for i in range(6 - module_data["amount"]):
                art += "|         |\n"
        art += "|_________|"
        return art
                

    
    @staticmethod
    def get_actions(module_name: str) -> list:
        if module_name == "Wires":
            return {"choices": {"wire number :" : ["cut", "don't cut"]}}
        elif module_name == "Button":
            return {"choices": {"written text": "placeholder", "button action :" : ["hold", "press"], "release when timer has :" : ["0", "1", "2", "3", "4", "5"]}}
        elif module_name == "Keypads":
            return {"choices": {"keypad sequence :" : "input"}}
        elif module_name == "Complicated Wires":
            return {"choices": {"wire number :" : ["cut", "don't cut"]}}
        else:
            raise ValueError(f"Unknown module name: {module_name}")
    
    @staticmethod
    def get_wire_data() -> dict:
        data = {}
        data["amount"] = random.randint(3, 6)
        data["colors"] = random.choices(["Red", "Blue", "White", "Yellow", "Black"], k=data["amount"]) # the order in the list is the order of the wires
        return data

    @staticmethod
    def get_wires_solution(module_data: dict, bomb: bomb) -> dict:
        if module_data["amount"] == 3:
            if "Red" not in module_data["colors"]:
                return {"cut": 2}
            elif module_data["colors"][-1] == "White":
                return {"cut": 3}
            elif module_data["colors"].count("Blue") > 1:
                return {"cut": last_index_of(module_data["colors"], "Blue") + 1}
            else:
                return {"cut": 3}
            
        elif module_data["amount"] == 4:
            if module_data["colors"].count("Red") > 1 and bomb.serial_digits[-1] % 2 == 1:
                return {"cut": last_index_of(module_data["colors"], "Red") + 1}
            elif module_data["colors"][-1] == "Yellow" and not "Red" in module_data["colors"]:
                return {"cut": 1}
            elif module_data["colors"].count("Blue") == 1:
                return {"cut": 1}
            elif module_data["colors"].count("Yellow") > 1:
                return {"cut": 4}
            else:
                return {"cut": 2}

        elif module_data["amount"] == 5:
            if module_data["colors"][-1] == "Black" and bomb.serial_digits[-1] % 2 == 1:
                return {"cut": 4}
            elif module_data["colors"].count("Red") == 1 and module_data["colors"].count("Yellow") > 1:
                return {"cut": 1}
            elif module_data["colors"].count("Black") == 0:
                return {"cut": 2}
            else:
                return {"cut": 1}
            
        elif module_data["amount"] == 6:
            if module_data["colors"].count("Yellow") == 0 and bomb.serial_digits[-1] % 2 == 1:
                return {"cut": 3}
            elif module_data["colors"].count("Yellow") == 1 and module_data["colors"].count("White") > 1:
                return {"cut": 4}
            elif module_data["colors"].count("Red") == 0:
                return {"cut": 6}
            else:
                return {"cut": 4}
            
        else:
            raise ValueError(f"Invalid amount of wires: {module_data['amount']}")
    
    @staticmethod
    def get_button_data() -> dict:
        data = {}
        data["color"] = random.choice(["Red", "Blue", "White", "Yellow", "Black"])
        data["text"] = random.choice(["Hold", "Press", "Abort", "Detonate"])
        data["color_strip"] = random.choice(["Red", "Blue", "White", "Yellow", "Pink", "Green"])
        return data
    
    @staticmethod
    def get_button_solution(module_data: dict, bomb: bomb) -> dict:
        def get_hold_solution(color: str) -> dict:
            if color == "Blue":
                return {"hold": 4} # 4 in any position of the timer
            elif color == "White":
                return {"hold": 1}
            elif color == "Yellow":
                return {"hold": 5}
            else:
                return {"hold": 1}
        
        if module_data["color"] == "Blue" and module_data["text"] == "Abort":
            return get_hold_solution(module_data["color_strip"])
        elif bomb.battery_amount > 1 and module_data["text"] == "Detonate":
            return {"hold": 0} # this means the button should be pressed and released immediately
        elif module_data["color"] == "White" and bomb.label == "CAR":
            return get_hold_solution(module_data["color_strip"])
        elif bomb.battery_amount > 2 and bomb.label == "FRK":
            return {"hold": 0}
        elif module_data["color"] == "Yellow":
            return get_hold_solution(module_data["color_strip"])
        elif module_data["color"] == "Red" and module_data["text"] == "Hold":
            return {"hold": 0}
        else:
            return get_hold_solution(module_data["color_strip"])
    
    @staticmethod
    def get_Complicated_Wires_data() -> dict:
        data = {}
        data["amount"] = random.randint(2, 6)
        data["colors"] = random.choices(["Red", "Blue", "Red and Blue", "White"], k=data["amount"])
        data["leds"] = [random.choice([True, False]) for _ in range(data["amount"])]
        data["stars"] = [random.choice([True, False]) for _ in range(data["amount"])]
        return data
    
    @staticmethod
    def get_Complicated_Wires_solution(module_data: dict, bomb: bomb) -> dict:
        possibilities = ['C', 'S', 'S', 'C', 'S', 'P', 'C', 'P', 'S', 'D', 'D', 'D', 'B', 'P', 'B', 'B']

        sets = {
                    'outside': set([0]),
                    'Red': set([1, 3, 4, 7, 8, 11, 12, 14]),
                    'Blue': set([2, 4, 5, 7, 8, 10, 11, 13]),
                    'Star': set([3, 6, 7, 10, 11, 13, 14, 15]),
                    'LED': set([5, 8, 9, 11, 12, 13, 14, 15])
        }
        solution = {}
        for i in range(module_data["amount"]):
            current = set()

            if module_data["colors"][i] == "Red":
                current |= sets['Red'] - sets['Blue']
            elif module_data["colors"][i] == "Blue":
                current |= sets['Blue'] - sets['Red']
            elif module_data["colors"][i] == "Red and Blue":
                current |= sets['Red'] & sets['Blue']
            
            if module_data["leds"][i]:
                if len(current) == 0:
                    current |= sets['LED'] - sets['Blue'] - sets['Red']
                else:
                    current &= sets['LED']
            else:
                current -= sets['LED']
            
            if module_data["stars"][i]:
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
            else:
                raise Exception(f"Invalid solution for Complicated Wires: {current}")
        
        output = []
        for i in range(module_data["amount"]):
            wire_index = i + 1
            solution_value = solution[wire_index]
            if possibilities[solution_value] == 'C':
                output.append("Cut")
            elif possibilities[solution_value] == 'S' and bomb.serial_digits[-1] % 2 == 0:
                output.append("Cut")
            elif possibilities[solution_value] == 'P' and 'parallel' in bomb.ports:
                output.append("Cut")
            elif possibilities[solution_value] == 'B' and bomb.battery_amount >= 2:
                output.append("Cut")
            else:
                output.append("Don't Cut")

        return output

    @staticmethod
    def symbols() -> list:
        return [
            ['Ϙ', 'Ѧ', 'ƛ', 'Ϟ', 'Ѭ', 'ϗ', 'Ͽ'],
            ['Ӭ', 'Ϙ', 'Ͽ', 'Ҩ', '☆', 'ϗ', '¿'],
            ['©', 'Ѽ', 'Ҩ', 'Җ', 'Ԇ', 'ƛ', '☆'],
            ['б', '¶', 'ƀ', 'Ѭ', 'Җ', '¿', 'ټ'],
            ['ψ', 'ټ', 'ƀ', 'Ͼ', '¶', 'Ѯ', '★'],
            ['б', 'Ӭ', '҂', 'æ', 'ψ', 'Ҋ', 'Ω'],
        ]
    
    @staticmethod
    def get_keypad_data() -> dict:
        return {'symbols': random.sample(random.choice(module.symbols()), k=4)}
    
    @staticmethod
    def get_keypad_solution(module_data: dict) -> list:
        for i in module.symbols():
            if len(set(module_data["symbols"]) & set(i)) == 4:
                solution = []
                for j in i:
                    if j in module_data["symbols"]:
                        solution.append(module_data["symbols"].index(j) + 1)
                return solution
    
    @staticmethod
    def get_random_modules(amount: int) -> list:
        return random.choices(module.modules(), k=amount)
