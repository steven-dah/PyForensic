from config import path_exists, ips_blacklist
from tkinter.messagebox import askyesno, showwarning
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import subprocess
import re
import requests
import time
import os

pyforensic_title = "PyForensic :"

def patterns():

    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    ipv6_pattern = (

        r'(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}|'
        r'(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}|'
        r'(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
        r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(?::0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.)'
        r'{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|'
        r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

        )

    return ipv4_pattern, ipv6_pattern

def blacklist():

    blacklist_path = Path(ips_blacklist)

    try:

        blacklist_path.write_text("", encoding="utf-8")

        if path_exists(ips_blacklist):

            while blacklist_path.stat().st_size == 0:

                subprocess.run(["notepad.exe", str(blacklist_path)])

                if blacklist_path.stat().st_size == 0:

                    empty_data = (

                        "The text document does not contain any data !"
                        "Please send IP addresses version 4 or 6."
                    
                        )

                    showwarning(title=pyforensic_title, message=empty_data)

            blacklist_created = (

                "The text document containing the IP addresses to be analysed has just been created !\n\n"
                "Would you like to analyse the addresses ?"

                )

            transmit_ips = askyesno(title=pyforensic_title, message=blacklist_created)

            if transmit_ips:

                return True
            
            else:
                
                return False

        else:

            return False

    except Exception:

        showwarning(title=pyforensic_title, message="The text document could not be created !")
        return False

def formatted_report(data, formatted_date, no_informations):

    return (

        f"Analysis for IP : {data.get('ipAddress') or no_informations}\n\n"
        f"AbuseIPDB scan results :\n\n"
        f"Public IP address : {data.get('isPublic') or no_informations}\n"
        f"IP - Version : {data.get('ipVersion') or no_informations}\n\n"
        f"On the whitelist : {data.get('isWhitelisted') or no_informations}\n\n"
        f"Confidence abuse score : {data.get('abuseConfidenceScore') or no_informations}\n\n"
        f"Country : {data.get('countryCode') or no_informations}\n\n"
        f"Type of use : {data.get('usageType') or no_informations}\n"
        f"ISP : {data.get('isp') or no_informations}\n"
        f"Domain : {data.get('domain') or no_informations}\n"
        f"Hostname : {data.get('hostnames') or no_informations}\n"
        f"Tor : {data.get('isTor') or no_informations}\n\n"
        f"Number of reports : {data.get('totalReports') or no_informations}\n"
        f"Number of distinct users : {data.get('numDistinctUsers') or no_informations}\n\n"
        f"Date of the last report : {formatted_date}\n\n"
        f"{'='*50}"

        )   

def ip_data(ip_entry, headers, no_informations):

    params = {
        
        "ipAddress": ip_entry, 
        "maxAgeInDays": "90" 
        
        }

    try:

        abuseipdb_request = requests.get(

            url="https://api.abuseipdb.com/api/v2/check", 
            headers=headers, 
            params=params
        
            )
        
        json_response = abuseipdb_request.json()
        data = json_response.get("data", {})
        
        raw_date = data.get('lastReportedAt')
        formatted_date = no_informations

        if raw_date:

            pattern = r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}).*'
            action = r'\3-\2-\1 at \4'
            match = re.match(pattern, raw_date)

            if match:

                formatted_date = re.sub(pattern, action, raw_date)

        return formatted_report(data, formatted_date, no_informations)

    except requests.exceptions.ConnectionError:

        showwarning(

            title=pyforensic_title, 
            message="An error occurred while analyzing an IP address with the AbuseIPDB API !"
        
            )
        
        return None

def result_thread(unique_ips, headers):

    first_result = True

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = {}

        for ip_address in unique_ips:

            task = executor.submit(ip_data, ip_address, headers, "N/A")
            futures[task] = ip_address

        for future in as_completed(futures):

            analysis_result = future.result()

            if analysis_result:

                if first_result:
                    
                    yield analysis_result
                    first_result = False

                else:
                    
                    yield "\n\n" + analysis_result
                
                time.sleep(2)

def run_analysis():

    load_dotenv()
    abuseipdb_key = os.getenv("ABUSEIPDB_API")

    blacklist_path = Path(ips_blacklist)
    content = blacklist_path.read_text(encoding="utf-8")

    ipv4_pattern, ipv6_pattern = patterns()

    ips_v4 = re.findall(ipv4_pattern, content)
    
    ips_v6 = []
    ipv6_matches = re.finditer(ipv6_pattern, content)

    for match in ipv6_matches:
        
        address = match.group(0)
        ips_v6.append(address)
    
    all_ips = ips_v4 + ips_v6
    unique_ips = set(all_ips)

    if not unique_ips:

        invalid_data = (

            "The data contained in the text document is invalid !\n\n"
            "Please only send IP addresses in version 4 or 6."
        
            )

        showwarning(title=pyforensic_title, message=invalid_data)
        return

    headers = { "Key": abuseipdb_key, "Accept": "application/json" }

    yield from result_thread(unique_ips, headers)

def ip():

    if not path_exists(ips_blacklist):

        missing_blacklist =  (

            "PyForensic did not detect any text document containing IP addresses to be analyzed !\n\n"
            "Would you like to create one ?"
        
            )

        create_blacklist = askyesno(title=pyforensic_title, message=missing_blacklist)

        if create_blacklist:

            if blacklist():

                return run_analysis()

            else: 
                
                return None

        else: 
            
            return None

    elif path_exists(ips_blacklist):

        return run_analysis()