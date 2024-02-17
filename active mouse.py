import pyautogui
import time

while True:
    # 当前鼠标位置
    current_mouse_x, current_mouse_y = pyautogui.position()
    # 移动鼠标
    pyautogui.move(10, 0)  # 水平向右移动10像素
    time.sleep(0.5)  # 等待0.5秒
    pyautogui.move(-10, 0)  # 水平向左移动10像素回到原位

    # 等待5分钟
    time.sleep(5)