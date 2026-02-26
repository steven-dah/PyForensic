from config import volatility_py, ram_dump
from tkinter.messagebox import showinfo

import subprocess
import os
import re

pyforensic_title = "PyForensic :"

def formatted_report(line_part):

    line = line_part.strip()

    rules = {

        r'\.000000$': '',
        r'\*': '',
        r'^0x[0-9a-fA-F]+$': None 

        }

    for pattern, action in rules.items():

        if action is None:
                    
            if re.match(pattern, line):
                        
                return None
                
        else:
                    
            line = re.sub(pattern, action, line)

    if line and all(line != character for character in ["-", "."]):

        return line

    return None

def network_data(line_content, excluded_words):

    if not line_content:

        return None

    for word in excluded_words:

        if word in line_content:

            return None

    raw_lines = line_content.split()
    formatted_lines = []

    for part in raw_lines:

        result = formatted_report(part)

        if result:

            formatted_lines.append(result)

    if formatted_lines:

        return " - ".join(formatted_lines)

    return None

def network():

    network_plugins = ["windows.netstat.NetStat"]

    excluded_words = [

        "Created", "ForeignAddr", "ForeignPort", "LocalAddr", "LocalPort",
        "Offset", "Owner", "PDB scanning finished", "PID", "Progress:",
        "Proto", "State", "Volatility"

        ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    def run_plugin(plugin):

        plugin_results = []

        plugin_command = subprocess.Popen(
            
                [
                
                "python", 
                volatility_py, 
                "-f", 
                ram_dump, 
                plugin
            
                ], 
            
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            env=env
            
            )

        for line in plugin_command.stdout:

            output_line = network_data(line.strip(), excluded_words)

            if output_line:

                plugin_results.append(output_line)

        if plugin_results:
            
            header = f"Plugin - {plugin} :\n\n"
            result = "\n".join(plugin_results)
            
            return header + result

        return None

    def run_analysis():

        first_result = True

        for plugin_name in network_plugins:

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