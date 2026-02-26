from config import path_exists, urls_blacklist
from tkinter.messagebox import askyesno, showwarning
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

import os
import subprocess
import re
import requests
import time

pyforensic_title = "PyForensic :"

def patterns():

    url_regex = r'https?://(?:www\.)?[\w\.-]+\.[a-zA-Z]{3}\b'
    
    return url_regex

def blacklist():

    try:

        if not os.path.exists(urls_blacklist):

            with open(urls_blacklist, "w", encoding="utf-8"):

                pass

        if path_exists(urls_blacklist):

            while os.path.getsize(urls_blacklist) == 0:

                subprocess.run(["notepad.exe", urls_blacklist])

                if os.path.getsize(urls_blacklist) == 0:

                    empty_data = (

                        "The text document does not contain any data !\n"
                        "Please transmit URLs."
                    
                        )

                    showwarning(title=pyforensic_title, message=empty_data)

            blacklist_created = (

                "The text document containing the URLs has just been created !\n\n"
                "Would you like to analyse the addresses ?"
                
                )
                
            transmit_urls = askyesno(title=pyforensic_title, message=blacklist_created)
            
            if transmit_urls:

                return True
            
            else:

                return False

        else:

            return False

    except Exception:

        showwarning(title=pyforensic_title, message="The text document could not be created !")
        return False

def formatted_report(response_data, no_informations):

    page = response_data.get("page", {})
    verdicts = response_data.get("verdicts", {}).get("overall", {})
    task = response_data.get("task", {})

    malicious = verdicts.get("malicious")

    if malicious:

        status = "Malicious"

    else:

        status = "Safe"

    return (

        f"Analysis for URL : {page.get('url') or no_informations}\n\n"
        f"URLScan scan results :\n\n"
        f"Verdict : {status} (Score: {verdicts.get('score') or no_informations})\n\n"
        f"IP address : {page.get('ip') or no_informations}\n"
        f"ISP : {page.get('asnname') or no_informations}\n"
        f"Geolocation : {page.get('city') or no_informations}, {page.get('country') or no_informations}\n\n"
        f"Screenshot : {task.get('screenshotURL') or no_informations}\n\n"
        f"Report URL : {task.get('reportURL') or no_informations}\n\n"
        f"{'='*50}"

        )

def url_data(url_entry, headers, no_informations):

    api_url = "https://urlscan.io/api/v1/scan"
    
    params = {
        
        "url": url_entry,
        "visibility": "public"
        
        }

    try:

        urlscan_request = requests.post(url=api_url, headers=headers, json=params)
        
        json_data = urlscan_request.json()
        uuid = json_data.get("uuid")

        if not uuid:
            
            showwarning(

                title=pyforensic_title, 
                message="An error occurred while retrieving the UUID of a domain name analysis report!"
                
                )
            
            return None
        
        else:
           
            time.sleep(25)

            urlscan_result = f"https://urlscan.io/api/v1/result/{uuid}/"
            urlscan_request = requests.get(url=urlscan_result, headers=headers)
            
            result_json = urlscan_request.json()
            
            return formatted_report(result_json, no_informations)

    except requests.exceptions.ConnectionError:

        showwarning(title=pyforensic_title, message="An error occurred while retrieving information from a URL !")
        return None

def result_thread(unique_urls, headers):

    first_result = True

    with ThreadPoolExecutor(max_workers=3) as executor:

        futures = {}

        for url_entry in unique_urls:

            task = executor.submit(url_data, url_entry, headers, "N/A")
            futures[task] = url_entry

        for future in as_completed(futures):

            analysis_result = future.result()

            if analysis_result:

                if first_result:

                    yield analysis_result
                    first_result = False

                else:

                    yield "\n\n" + analysis_result

def run_analysis():

    load_dotenv()
    urlscan_key = os.getenv("URLSCAN_API")

    unique_urls = set()
    url_regex = patterns()
    
    try:

        with open(urls_blacklist, "r", encoding="utf-8") as blacklist_file:
            
            content = blacklist_file.read()
            matches = re.findall(url_regex, content)
            
            for clean_url in matches:
                
                unique_urls.add(clean_url)

    except Exception:

        return

    if not unique_urls:

        invalid_data = (

            "The data contained in the text document is invalid !\n\n"
            "Please provide valid URLs starting with http/https."
            
            )

        showwarning(title=pyforensic_title, message=invalid_data)
        return

    headers = { 

        "Content-Type": "application/json",
        "API-Key": urlscan_key 
    
        }

    yield from result_thread(unique_urls, headers)

def url():

    if not path_exists(urls_blacklist):

        missing_blacklist = (

            "PyForensic did not detect any text document containing URLs to be analyzed !\n\n"
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

    elif path_exists(urls_blacklist):

        return run_analysis()