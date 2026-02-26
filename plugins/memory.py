from config import volatility_py, ram_dump
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter.messagebox import showinfo

import subprocess
import os

pyforensic_title = "PyForensic :"

def formatted_report(line_part):

    replace_line = (

        line_part.strip().replace("::", "").replace("*", "")
        
        )

    if replace_line and all(replace_line != character for character in ["-", "."]):

        return replace_line

    return None

def memory_data(line_content, excluded_words):

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

def memory():

    memory_plugins = [

        "windows.bigpools",
        "windows.poolscanner",
        "windows.vadinfo",
        "windows.vadwalk",
        "windows.virtmap"

        ]

    excluded_words = [
        
        "100.00", "Allocation", "Charge", "CommitCharge", "End",
        "File", "finished", "Left", "NumberOfBytes", "Offset",
        "output", "Parent", "PDB", "PID", "PoolType",
        "PrivateMemory", "Process", "Progress", "Protection", "Right",
        "rogress", "scanning", "Start", "Status", "Tag",
        "Volatility 3", "VPN"

        ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    def run_plugin(plugin):

        plugin_results = []

        command_args = [
            
            "python", 
            volatility_py, 
            "-f", 
            ram_dump, 
            plugin
            
            ]

        plugin_thread = subprocess.Popen(
            
            command_args, 

            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            env=env
            
            )

        for line in plugin_thread.stdout:

            output_line = memory_data(line.strip(), excluded_words)

            if output_line:

                plugin_results.append(output_line)

        plugin_thread.wait()

        if plugin_results:
            
            header = f"Plugin - {plugin} :\n\n"
            result = "\n".join(plugin_results)
            
            return header + result
        
        return None

    def result_thread(futures):

        first_result = True

        for future in as_completed(futures):

            plugin_result = future.result()

            if plugin_result:

                output = plugin_result

                if not first_result:

                    yield "\n\n" + output

                else:

                    yield output
                    first_result = False

    def run_analysis():

        with ThreadPoolExecutor(max_workers=5) as executor:

            futures = {
                
                executor.submit(run_plugin, name): name 
                for name in memory_plugins
                
                }

            yield from result_thread(futures)

    yield from run_analysis()

    showinfo(

        title=pyforensic_title, 
        message="The complete display of plugins results has been successfully displayed !"
    
        )