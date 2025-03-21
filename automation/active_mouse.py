import pyautogui
import time
import random
import sys
from datetime import datetime

def move_mouse():
    """
    Move the mouse to prevent system from sleeping
    """
    try:
        # Get screen size
        screen_width, screen_height = pyautogui.size()
        
        while True:
            # Generate random coordinates within screen bounds
            x = random.randint(0, screen_width)
            y = random.randint(0, screen_height)
            
            # Move mouse to random position
            pyautogui.moveTo(x, y, duration=0.5)
            
            # Log movement
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] Mouse moved to position ({x}, {y})")
            
            # Random delay between 10-30 seconds
            delay = random.randint(10, 30)
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\nMouse movement stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("Starting mouse movement. Press Ctrl+C to stop.")
    move_mouse()