#!/usr/bin/env python3
import random
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/dev/stdout')
    ]
)

def generate_random():
    """Генерирует случайное число и записывает в лог"""
    random_num = random.randint(1, 1000)
    logging.info(f"Сгенерировано случайное число: {random_num}")

if __name__ == "__main__":
    generate_random()