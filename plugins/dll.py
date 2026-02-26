from config import volatility_py, ram_dump
from tkinter.messagebox import showinfo

import subprocess
import os
import re

pyforensic_title = "PyForensic :"

def formatted_report(line_part):

    line = line_part.replace("-", "")

    rules = {

        r'^0x[0-9a-fA-F]+$': None,
        r'^(True|False|UTC|N/A)$': None,
        r'^(\d{2}:\d{2}:\d{2})\.000000$': r'\1',
        r'^(\d{4})-(\d{2})-(\d{2})$': r'\3-\2-\1',
        r'^(\d{4})(\d{2})(\d{2})$': r'\3-\2-\1'
                
        }

    for pattern, action in rules.items():

        match = re.match(pattern, line)

        if match:

            if action is None:

                line = None

            else:
                        
                line = re.sub(pattern, action, line)
                    
            break

    if line:

        time_match = re.match(r'^(\d{6})\.000000$', line)

        if time_match:

            value = time_match.group(1)
            line = f"{value[:2]}:{value[2:4]}:{value[4:6]}"

    return line

def dll_data(line_content, excluded_words):

    if not line_content:

        return None

    for word in excluded_words:

        if word in line_content:

            return None

    raw_lines = line_content.split()
    formatted_lines = []

    for line_part in raw_lines:

        line = formatted_report(line_part)

        if line and all(line != character for character in ["-", "."]):

            formatted_lines.append(line)

    if formatted_lines:

        return " - ".join(formatted_lines)

    return None

def dll():

    dll_plugins = ["windows.dlllist.DllList"]

    excluded_words = [

        "Base", "File", "Finished", "Framework", "LoadCount",
        "LoadTime", "Name", "Output", "Path", "PDB", "PID",
        "Process", "Progress", "Scanning", "Size", "Volatility"

        ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    def run_plugin(plugin):

        plugin_results = []

        plugin_command = subprocess.Popen([
            
            "python", 
            volatility_py, 
            "-f", 
            ram_dump, 
            plugin], 

            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            env=env
            
            )

        for line in plugin_command.stdout:

            output_line = dll_data(line.strip(), excluded_words)

            if output_line:

                plugin_results.append(output_line)

        if plugin_results:

            header = f"Plugin - {plugin} :\n\n"
            result = "\n".join(plugin_results)

            return header + result
        
        return None

    def run_analysis():

        first_result = True

        for plugin_name in dll_plugins:

            output = run_plugin(plugin_name)

            if output:

                if not first_result:

                    yield "\n\n" + output

                else:

                    yield output
                    first_result = False

    yield from run_analysis()

    showinfo(

        title=pyforensic_title, 
        message="The complete display of plugins results has been successfully displayed !"
    
        )