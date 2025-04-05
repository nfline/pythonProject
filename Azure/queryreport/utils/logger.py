import logging
from colorama import Fore, Style

class ColorPrinter:
    @staticmethod
    def print_info(text):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {text}")

    @staticmethod
    def print_success(text):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {text}")

    @staticmethod
    def print_warning(text):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {text}")

    @staticmethod
    def print_error(text):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {text}")

def setup_logger():
    logger = logging.getLogger("NSGLogger")
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    fh = logging.FileHandler('nsg_analysis.log')
    fh.setFormatter(formatter)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger