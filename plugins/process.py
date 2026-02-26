from config import path_join, path_exists, volatility_py, ram_dump, dumps_directory, hahs_txt
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter.messagebox import showinfo

import subprocess
import os
import hashlib
import shutil
import re

pyforensic_title = "PyForensic :"

def formatted_report(line_part):

    line = line_part.strip()

    rules = {

        r'\.000000$': '',
        r'\*': '',
        r'^0x[0-9a-fA-F]+$': None,
        r'.*\.dmp$': None

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

def process_data(line_content, excluded_words):

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

def process():

    process_plugins = [

        "windows.cmdscan",
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.pstree.PsTree"

        ]

    excluded_words = [

        "CreateTime", "ExitTime", "Handles", "Offset", "output",
        "PDB", "PID", "PPID", "Progress:", "SessionId", 
        "Threads", "Volatility", "Wow64"

        ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    def run_plugin(plugin):

        plugin_results = []

        command = [
            
            "python", 
            volatility_py, 
            "-f", 
            ram_dump, 
            "-o",
            dumps_directory,
            plugin
            
            ]
        
        if plugin == "windows.pslist.PsList":
            
            command.append("--dump")

            if not path_exists(dumps_directory):
            
                os.makedirs(dumps_directory)

        plugin_thread = subprocess.Popen(

            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            env=env
            
            )

        for line in plugin_thread.stdout:

            output_line = process_data(line.strip(), excluded_words)

            if output_line:

                plugin_results.append(output_line)

        plugin_thread.wait()

        if plugin == "windows.pslist.PsList":

            if path_exists(hahs_txt):

                os.remove(hahs_txt)

            if path_exists(dumps_directory):

                with open(hahs_txt, "a", encoding="utf-8") as hash_file:

                    for dump_name in os.listdir(dumps_directory):
                            
                        if dump_name.endswith(".dmp"):

                            name_dumps = dump_name.split(".")

                            formatted_name = f"{name_dumps[1]}.dmp" if len(name_dumps) >= 2 else dump_name

                            dump_path = path_join(dumps_directory, dump_name)
                            sha256_hash = hashlib.sha256()

                            with open(dump_path, "rb") as dump_file:

                                for byte_block in iter(lambda: dump_file.read(4096), b""):
                                
                                    sha256_hash.update(byte_block)
                            
                            hash_file.write(f"{formatted_name} : {sha256_hash.hexdigest()}\n")

                shutil.rmtree(dumps_directory)

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

        with ThreadPoolExecutor(max_workers=3) as executor:

            futures = {executor.submit(run_plugin, name): name for name in process_plugins}

            yield from result_thread(futures)

    yield from run_analysis()

    showinfo(

        title=pyforensic_title, 
        message="The complete display of plugins results has been successfully displayed !"
    
        )