from config import volatility_py, ram_dump
from tkinter.messagebox import showinfo
from concurrent.futures import ThreadPoolExecutor, as_completed

import subprocess
import os
import re

pyforensic_title = "PyForensic :"

def formatted_report(line_part):

    line = line_part.strip().replace("::", "").replace("*", "")

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

def registry_data(line_content, excluded_words):

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

def registry():

    registry_plugins = [

        "windows.registry.amcache.Amcache",
        "windows.registry.certificates.Certificates",
        "windows.registry.getcellroutine.GetCellRoutine",
        "windows.registry.hivelist.HiveList",
        "windows.registry.hivescan.HiveScan",
        "windows.registry.printkey.PrintKey",
        "windows.registry.scheduled_tasks.ScheduledTasks",
        "windows.registry.userassist.UserAssist"

        ]

    excluded_words = [
        
        "100.00", "2.28.0", "3", "Action", "Arguments",
        "Certificate", "CompileTime", "Company", "Context", "Count",
        "Creation", "Data", "Description", "Directory", "Display",
        "Enabled", "EntryType", "File", "FileFullPath", "finished",
        "Focus", "Focused", "Framework", "GetCellRoutine", "Handler",
        "Hive", "ID", "InstallTime", "Key", "Last",
        "LastModifyTime", "LastModifyTime2", "LastRunTime", "LastSuccessfulRunTime", "LastUpdated",
        "LastWriteTime", "Module", "Name", "Offset", "output",
        "Path", "PDB", "Principal", "ProductName", "ProductVersion",
        "Progress:", "Raw", "Run", "scanning", "section",
        "Service", "SHA1", "Successful", "Task", "Time",
        "Trigger", "Type", "Updated", "Volatile", "Volatility",
        "Working", "Write"
        
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

            output_line = registry_data(line.strip(), excluded_words)

            if output_line:

                plugin_results.append(output_line)

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

        with ThreadPoolExecutor(max_workers=4) as executor:

            futures = {}

            for plugin_name in registry_plugins:

                future = executor.submit(run_plugin, plugin_name)
                futures[future] = plugin_name

            yield from result_thread(futures)

    yield from run_analysis()

    showinfo(

        title=pyforensic_title, 
        message="The complete display of plugins results has been successfully displayed !"

        )