import os
import time

def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open(log_file, "a") as file:
        file.write(f"{message}\n")
