from config import script_directory, path_join, path_exists, proxy_blacklist, denied_html
from mitmproxy import http
from tkinter.messagebox import askyesno, showwarning, showinfo

import sys
import threading
import subprocess

pyforensic_title = "PyForensic :"

def request(flow: http.HTTPFlow):

    run_proxy = False

    if not path_exists(proxy_blacklist):

        blacklist_missing = (

            "PyForensic did not detect any text documents containing blacklists of malicious or pornographic domains !\n\n"
            "Would you like to create one ?"
        
            )

        create_blacklist = askyesno(title=pyforensic_title, message=blacklist_missing)

        if create_blacklist:
            
            try:
                        
                with open(proxy_blacklist, "w", encoding="utf-8"):
                            
                    pass

                if path_exists(proxy_blacklist):

                    transmit_domains = (

                        "The text document blacklists of malicious or pornographic domains has just been created !\n\n"
                        "Would you like to transmit domains ?"
                            
                        )
                            
                    information_creation = askyesno(title=pyforensic_title, message=transmit_domains)

                    if information_creation:

                        subprocess.run(["notepad.exe", proxy_blacklist])

                        run_proxy = True

                    else:

                        sys.exit()

            except Exception:

                    showwarning(title=pyforensic_title, message="The text document could not be created !")
                    sys.exit()

    elif path_exists(proxy_blacklist):
        
        run_proxy = True

    if run_proxy:
        
        with open(proxy_blacklist, "r", encoding="utf-8") as blacklist:

            hosts = []

            for line in blacklist:

                line_content = line.strip()

                if line_content:

                    hosts.append(line_content)

            unique_domains = set(hosts)

            current_host = flow.request.pretty_host

            is_blocked = False

            for host in unique_domains:

                if host in current_host:

                    is_blocked = True

                    break

            if is_blocked:

                if path_exists(denied_html):

                    with open(denied_html, "rb") as denied:

                        flow.response = http.Response.make(

                            403,
                            denied.read(),
                            {"Content-Type": "text/html"}
                    
                            )

def proxy():

    subprocess.Popen([
        
        "mitmproxy", "-s",
        path_join(script_directory, "proxy.py"),"--listen-port", "8080"],
        creationflags=subprocess.CREATE_NO_WINDOW
        
        )
    
    showinfo(title=pyforensic_title, message="The MITMPROXY server analyzes your traffic via the local IP address and port 8080 !")
    
if __name__ == "__main__":

    threading.Thread(target=proxy).start()