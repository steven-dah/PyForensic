from config import script_directory, dumpit_exe, volatility_path, path_exists, ram_dump, ram_json
from tkinter.messagebox import askyesno, showinfo, showwarning, showerror
from git import Repo

import pathlib
import wget
import os
import subprocess
import sys

def dumpit(software_current, pyforensic_title):

    if not software_current.exists():

        dumpit_url = "https://github.com/h4sh5/DumpIt-mirror/raw/main/DumpIt.exe"
        wget.download(url=dumpit_url, out=str(software_current))

        os.system("cls")

    if software_current.exists():

        dumpit_info = (

            "DumpIt is ready !\n"
            "Would you like to dump the RAM ?"
        
            )

        perform_dump = askyesno(title=pyforensic_title, message=dumpit_info)

        if perform_dump:

            try:

                ram_extraction = subprocess.run(

                    str(software_current), 
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    shell=True
                
                    )

                if ram_extraction.returncode == 0:

                    dmp_file = list(pathlib.Path(script_directory).glob("*.dmp"))
                    json_file = list(pathlib.Path(script_directory).glob("*.json"))

                    for files, target in [(dmp_file, ram_dump), (json_file, ram_json)]:

                        if files:

                            pathlib.Path(files[0]).replace(target)

                    if path_exists(ram_dump) and path_exists(ram_json):

                        showinfo(title=pyforensic_title, message="The RAM dump has just been completed !")

                    else:

                        showwarning(title=pyforensic_title, message="The RAM dump could not be created !")

            except Exception:

                    showerror(title=pyforensic_title, message="An error occurred while extracting the RAM !")
        
        else:

            sys.exit()

def volatility(software_current, pyforensic_title):

    volatility_url = "https://github.com/volatilityfoundation/volatility3"

    try:
        
        Repo.clone_from(volatility_url, to_path=str(software_current))

        if software_current.exists():

            showinfo(title=pyforensic_title, message="Volatility has just been downloaded !")

        else:

            showwarning(title=pyforensic_title, message="Volatility could not be downloaded !")
            sys.exit()

    except Exception: 

        showerror(title=pyforensic_title, message="An error occurred while downloading Volatility !")
        sys.exit()

def softwares():

    pyforensic_title = "PyForensic :"

    softwares_list = [

        dumpit_exe,
        volatility_path

        ]
    
    for software_path in softwares_list:

        software_current = pathlib.Path(software_path)

        if software_current.name == "DumpIt.exe":

            if path_exists(ram_dump) and path_exists(ram_json):

                continue

        if not software_current.exists():

            requirements_info = (

                f"PyForensic has detected that {software_current.name} is missing !\n"
                "Would you like to download it ?"
            
                )
            
            download_requirements = askyesno(title=pyforensic_title, message=requirements_info)

            if download_requirements:

                if software_current.name == "DumpIt.exe":

                    dumpit(software_current, pyforensic_title)

                elif "volatility" in software_current.name.lower():

                    volatility(software_current, pyforensic_title)

            else:

                sys.exit()

        else:

            if software_current.name == "DumpIt.exe":
                
                if not path_exists(ram_dump) or not path_exists(ram_json):

                    dumpit(software_current, pyforensic_title)

if __name__ == "__main__":

    softwares()