import subprocess
import json
from .logger import ColorPrinter

def run_az_command(command):
    """执行Azure CLI命令并返回JSON结果"""
    try:
        result = subprocess.run(
            f"az {command} -o json",
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        ColorPrinter.print_error(f"命令执行失败: {e.stderr}")
        return None
    except json.JSONDecodeError:
        ColorPrinter.print_warning("返回结果不是有效JSON格式")
        return result.stdout

def check_az_login():
    """检查Azure登录状态"""
    try:
        subprocess.run(
            "az account show",
            shell=True,
            check=True,
            capture_output=True
        )
        ColorPrinter.print_success("Azure CLI已登录")
        return True
    except subprocess.CalledProcessError:
        ColorPrinter.print_error("请先执行 az login 登录Azure账户")
        return False