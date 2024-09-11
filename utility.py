import os
import json 
from typing import List, Dict
import traceback
import subprocess
def get_elements_m_to_n(hashes, from_n, to_n):
    result = {}
    for i, (key, value) in enumerate(hashes.items()):
        if from_n <= i <= to_n:
            result[key] = value
    return result

def run_command(command):
    subprocess.run(command, shell=True, check=True)

