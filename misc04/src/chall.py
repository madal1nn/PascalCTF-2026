from utils import bomb, module
import os
import signal
import sys

FLAG = os.environ.get("FLAG", "pascalCTF{H0w_4r3_Y0u_s0_g0Od_4t_BOMBARE}")
TIMEOUT = int(os.environ.get("TIMEOUT", "300"))

MODULES = int(os.environ.get("MODULES", "5"))
bomb = bomb(MODULES)

def timeout_handler(signum, frame):
    print("\n⏰ TIME'S UP! ⏰")
    print("💥 The bomb exploded due to timeout!")
    print("🎮 Game Over! Try to be faster next time.")
    sys.exit(1)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT)

def main():
    title = """
         )            (      (           (    (    (           (        )          
  ( /(            )\\ )   )\\ )   (    )\\ ) )\\ ) )\\ )  *   ) )\\ )  ( /(  (       
  )\\()) (    (   (()/(  (()/(   )\\  (()/((()/((()/(` )  /((()/(  )\\()) )\\ )    
 ((_)\\  )\\   )\\   /(_))  /(_))(((_)  /(_))/(_))/(_))( )(_))/(_))((_)\\ (()/(    
 _ ((_)((_) ((_) (_))   (_))  )\\___ (_)) (_)) (_)) (_(_())(_))   _((_) /(_))_  
| |/ / | __|| __|| _ \\  / __|((/ __|| _ \\|_ _|| _ \\|_   _||_ _| | \\| |(_)) __| 
| ' <  | _| | _| |  _/  \\__ \\ | (__ |   / | | |  _/  | |   | |  | .` |  | (_ | 
|_|\\_\\ |___||___||_|    |___/  \\___||_|_\\|___||_|    |_|  |___| |_|\\_|   \\___| 
                                                                               
    """

    art = """
                 .               
                 .               
                 .       :       
                 :      .        
        :..   :  : :  .          
           ..  ; :: .            
              ... .. :..         
             ::: :...            
         ::.:.:...;; .....       
      :..     .;.. :;     ..     
            . :. .  ;.           
             .: ;;: ;.           
            :; .BRRRV;           
               YB BMMMBR         
              ;BVIMMMMMt         
        .=YRBBBMMMMMMMB          
      =RMMMMMMMMMMMMMM;          
    ;BMMR=VMMMMMMMMMMMV.         
   tMMR::VMMMMMMMMMMMMMB:        
  tMMt ;BMMMMMMMMMMMMMMMB.       
 ;MMY ;MMMMMMMMMMMMMMMMMMV       
 XMB .BMMMMMMMMMMMMMMMMMMM:      
 BMI +MMMMMMMMMMMMMMMMMMMMi      
.MM= XMMMMMMMMMMMMMMMMMMMMY      
 BMt YMMMMMMMMMMMMMMMMMMMMi      
 VMB +MMMMMMMMMMMMMMMMMMMM:      
 ;MM+ BMMMMMMMMMMMMMMMMMMR       
  tMBVBMMMMMMMMMMMMMMMMMB.       
   tMMMMMMMMMMMMMMMMMMMB:        
    ;BMMMMMMMMMMMMMMMMY          
      +BMMMMMMMMMMMBY:           
        :+YRBBBRVt;
    """

    print(title)
    print(art)
    
    play_game(bomb)

def play_game(bomb):
    print(f"Modules to defuse: {len(bomb.modules)}")
    print(f"Serial Number: {''.join(map(str, bomb.serial_digits))}")
    print(f"Batteries: {bomb.battery_amount}")
    print(f"Label: {bomb.label}")
    print(f"Ports: {', '.join(bomb.ports)}")
    print("=" * 50)
    
    modules_defused = 0
    
    for i, current_module in enumerate(bomb.modules):
        print(f"\n📍 Module {i+1}/{len(bomb.modules)}")
        print(f"Modules remaining: {len(bomb.modules) - modules_defused}")
        
        while True:
            print(f"\n> Select Module {i+1} to defuse (press Enter): ", end="")
            input()  # Wait for user to press Enter
            
            # Module information
            print(f"\n🔧 Module: {current_module.name}")
            print(current_module.get_art_from_name(current_module.name, current_module.data))
            print(f"Data: {current_module.data}")
            
            # Get player's solution
            solution_input = get_player_solution(current_module)
            
            # Check solution
            if validate_solution(current_module, solution_input):
                print("✅ Module defused successfully!")
                modules_defused += 1
                break
            else:
                signal.alarm(0)
                print("💥 BOOM! Wrong solution!")
                print(f"💡 Correct answer was: {current_module.solution}")
                print("🎮 Game Over! Try again.")
                return False
    
    # All modules defused
    signal.alarm(0)
    print("\n🎉 CONGRATULATIONS! 🎉")
    print("🏆 You successfully defused the bomb!")
    print(f"🚀 Well done, here's your flag: {FLAG}")
    return True

def get_player_solution(current_module):
    """Get solution input from player based on module type"""
    print(f"\n📝 Enter your solution for {current_module.name}:")
    
    if current_module.name == "Wires":
        while True:
            try:
                wire_num = int(input("Which wire to cut (enter wire number): "))
                if 1 <= wire_num <= current_module.data["amount"]:
                    return {"cut": wire_num}
                else:
                    print(f"Invalid wire number. Choose between 1 and {current_module.data['amount']}")
            except ValueError:
                print("Please enter a valid number")
    
    elif current_module.name == "Button":
        print("Button options:")
        print("1. Press and release immediately")
        print("2. Hold until timer shows specific digit")
        
        while True:
            try:
                action = int(input("Choose action (1 or 2): "))
                if action == 1:
                    return {"hold": 0}
                elif action == 2:
                    digit = int(input("Release when timer shows digit (0-9): "))
                    if 0 <= digit <= 9:
                        return {"hold": digit}
                    else:
                        print("Enter a digit between 0 and 9")
                else:
                    print("Choose 1 or 2")
            except ValueError:
                print("Please enter a valid number")
    
    elif current_module.name == "Keypads":
        print("Enter the sequence of keypad positions (1-4) in order:")
        while True:
            try:
                sequence_str = input("Sequence (e.g., '1 3 2 4'): ")
                sequence = [int(x) for x in sequence_str.split()]
                if len(sequence) == 4 and all(1 <= x <= 4 for x in sequence):
                    return sequence
                else:
                    print("Enter exactly 4 numbers between 1 and 4")
            except ValueError:
                print("Please enter numbers separated by spaces")
    
    elif current_module.name == "Complicated Wires":
        print("For each wire, enter 'cut' or 'skip':")
        result = []
        for i in range(current_module.data["amount"]):
            while True:
                action = input(f"Wire {i+1}: ").lower().strip()
                if action in ['cut', 'skip', 'don\'t cut']:
                    result.append("Cut" if action == 'cut' else "Don't Cut")
                    break
                else:
                    print("Enter 'cut' or 'skip'")
        return result
    
    return None

def validate_solution(current_module, player_solution):
    correct_solution = current_module.solution
    
    if current_module.name in ["Wires", "Button"]:
        return player_solution == correct_solution
    elif current_module.name == "Keypads":
        return player_solution == correct_solution
    elif current_module.name == "Complicated Wires":
        return player_solution == correct_solution
    
    return False

if __name__ == "__main__":
    main()
