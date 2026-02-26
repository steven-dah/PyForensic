from config import path_exists, dejasvusans_ttf, analysis_report
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter.messagebox import showwarning, showinfo
from groq import Groq
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import simpleSplit
from pathlib import Path

import os
import threading
import wget
import requests
import hashlib
import time

class Analyze:

    def __init__(self):

        load_dotenv()

        self.malwarebazaar_key = os.getenv("MALWAREBAZAAR_API")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API")
        self.groq_key = os.getenv("GROQ_API")

        self.dejavusans_font = "DejaVuSans"
        self.pyforensic_title = "PyForensic :"
        
        self.malwarebazaar_quota = False
        self.virustotal_quota = False
        
        self.lock = threading.Lock()

    def malwarebazaar_data(self, binary, malware_hash, no_informations):

        malwarebazaar_informations = []
        malwarebazaar_url = "https://mb-api.abuse.ch/api/v1/"
        
        params = {

            "query": "get_info",
            "hash": malware_hash
    
            }

        malwarebazaar_headers = {

            "Auth-Key": self.malwarebazaar_key
    
            }

        try:

            malwarebazaar_request = requests.post(

                malwarebazaar_url, 
                data=params, 
                headers=malwarebazaar_headers, 
                timeout=15
            
                )

            if malwarebazaar_request.status_code == 200:

                malwarebazaar_result = malwarebazaar_request.json()
        
                if malwarebazaar_result.get("query_status") == "ok":

                    malwarebazaar_data = malwarebazaar_result.get("data", [{}])[0]
                    malwarebazaar_vendor = malwarebazaar_data.get("vendor_intel", {})

                    malwarebazaar_report = (
                        
                        f"Analysis for binary : {binary}\n\n"
                        f"MalwareBazaar scan results :\n\n"
                        f"Binary name : {malwarebazaar_data.get('file_name') or no_informations}\n\n"
                        f"SHA-256 : {malwarebazaar_data.get('sha256_hash') or no_informations}\n"
                        f"SHA-1 : {malwarebazaar_data.get('sha1_hash') or no_informations}\n"
                        f"MD5 : {malwarebazaar_data.get('md5_hash') or no_informations}\n\n"
                        f"Date of first detection : {malwarebazaar_data.get('first_seen') or no_informations}\n"
                        f"Date of last detection : {malwarebazaar_data.get('last_seen') or no_informations}\n\n"
                        f"Country of origin : {malwarebazaar_data.get('origin_country') or no_informations}\n\n"
                        "Verdict on the danger of the binary :\n\n"
                        f"- InQuest : {malwarebazaar_vendor.get('InQuest', {}).get('verdict', no_informations)}\n"
                        f"- Triage Score : {malwarebazaar_vendor.get('Triage', {}).get('score', no_informations)}/10\n"
                        f"- FileScan.io : {malwarebazaar_vendor.get('FileScan-IO', {}).get('verdict', no_informations)}\n"
                        f"- Yoroi Yomi : {malwarebazaar_vendor.get('YOROI_YOMI', {}).get('detection', no_informations)}\n"
                        f"- ReversingLabs : {malwarebazaar_vendor.get('ReversingLabs', {}).get('status', no_informations)}\n"
                        
                        )

                    malwarebazaar_informations.append(malwarebazaar_report)

                elif malwarebazaar_result.get("query_status") == "hash_not_found":
            
                    malwarebazaar_informations.append(f"Binary analysis results : {binary}\n")
                    malwarebazaar_informations.append("MalwareBazaar scan results :\n")
                    malwarebazaar_informations.append("N/A")

                else:

                    malwarebazaar_informations.append(f"Unexpected status from MalwareBazaar for {binary} !")

            elif malwarebazaar_request.status_code == 429:

                malwarebazaar_exeeded = (

                    "You have exceeded the quota allowed by MalwareBazaar !\n"
                    "Please do not exceed 500 requests and try again tomorrow."

                    )

                with self.lock:

                    if not self.malwarebazaar_quota:

                        showinfo(title=self.pyforensic_title, message=malwarebazaar_exeeded)
                        self.malwarebazaar_quota = True

                malwarebazaar_informations.append(malwarebazaar_exeeded)

        except Exception:
            
            malwarebazaar_informations.append(f"An error occurred while querying MalwareBazaar for {binary} !")

        return malwarebazaar_informations

    def virustotal_data(self, malware_hash, no_informations):

        virustotal_informations = []
        virustotal_url = "https://www.virustotal.com/api/v3/files/" + malware_hash
        
        virustotal_headers = {
    
            "accept": "application/json",
            "x-apikey": self.virustotal_key
                
            }

        try:

            virustotal_request = requests.get(

                virustotal_url, 
                headers=virustotal_headers, 
                timeout=15
                
                )

            if virustotal_request.status_code == 200:

                virustotal_results = virustotal_request.json()
                data = virustotal_results.get("data", {})
                attributes = data.get("attributes", {})

                last_analysis_results = attributes.get("last_analysis_results", {})
                analysis_reports = []

                for engine in last_analysis_results.values():

                    engine_name = engine.get("engine_name")
                    category = engine.get("category")
                    result = engine.get("result")

                    if not result:

                        result = no_informations

                    analysis_reports.append(f"{engine_name} : {category} - {result}")
                
                analysis_string = ""

                if analysis_reports:

                    analysis_string = "\n".join(analysis_reports)

                else:

                    analysis_string = no_informations

                threat_classification = attributes.get("popular_threat_classification", {})
                threat_categories = threat_classification.get("popular_threat_category", [])
                
                threat_summaries = []

                for category in threat_categories:

                    value = str(category.get("value"))
                    value = value.capitalize()
                    count = category.get("count")
                    threat_summaries.append(f"{value} - {count} %")
                
                threat_string = ""

                if threat_summaries:

                    threat_string = "\n".join(threat_summaries)

                else:

                    threat_string = no_informations

                virustotal_report = (

                    "VirusTotal scan results :\n\n"
                    f"{analysis_string}\n"
                    f"\nVirusTotal - Binary classification{'s' if len(threat_summaries) > 1 else ''} :\n\n"
                    f"{threat_string}\n\n"

                    )

                virustotal_informations.append(virustotal_report)

            elif virustotal_request.status_code == 429:

                virustotal_exceeded = (

                    "You have exceeded the quota allowed by VirusTotal !\n"
                    "Please do not exceed 500 requests and try again tomorrow."
                
                    )

                with self.lock:

                    if not self.virustotal_quota:

                        showinfo(title=self.pyforensic_title, message=virustotal_exceeded)
                        self.virustotal_quota = True

                virustotal_informations.append(virustotal_exceeded)

        except Exception:

            virustotal_informations.append("\nAn error occurred while retrieving the results of the binary analysis with the VirusTotal API !")

        return virustotal_informations
    
    def groq_conclusion(self, results):

        syntax_information = "IMPORTANT : Please use ONLY plain text paragraphs without markdown, tables, hashtags, dashes and special symbols !"

        client = Groq(api_key=self.groq_key)
        
        full_result = "\n".join(results)
        chunk_size = 20000
        
        chunks = []

        for i in range(0, len(full_result), chunk_size):

            segment = full_result[i:i + chunk_size]
            chunks.append(segment)
        
        try:

            partial_summaries = []

            for chunk in chunks:

                completion = client.chat.completions.create(
                    
                    model="openai/gpt-oss-120b",
                    messages=[

                        {
                            "role": "user",
                            "content": (

                                "Summarize this malware analysis report !"
                                f"{syntax_information}"
                                f"Content : {chunk}"
                            
                                )
                        }

                    ]
                )
                
                partial_summaries.append(completion.choices[0].message.content)

            summary = "\n".join(partial_summaries)
            
            final_completion = client.chat.completions.create(
               
                model="openai/gpt-oss-120b",
                messages=[

                    {
                        "role": "user",
                        "content": (

                            f"{syntax_information}"
                            f"As a SOC analyst, provide a final global conclusion and executive summary based on these aggregated findings : {summary}"
                        
                            )
                    }
                ]
            )

            return final_completion.choices[0].message.content

        except Exception as e:

            if "429" in str(e):

                showinfo(title=self.pyforensic_title, message="The Gorq analysis report cannot be generated because the daily quota limit has been exceeded !")
                return None

            return None

    def pdf_report(self, results, conclusion):

        def deja_font():

            pdfmetrics.registerFont(TTFont("DejaVuSans", dejasvusans_ttf))

        def pdf_position(line, current_y):

            if current_y < margin:

                report.showPage()
                report.setFont(self.dejavusans_font, 10)
                
                current_y = height - margin

            if line.strip() == "":

                current_y -= 12
                return current_y

            wrapped = simpleSplit(

                line, 
                self.dejavusans_font, 
                10, 
                width - (2 * margin)
                
                )

            for chunk in wrapped:

                report.drawString(margin, current_y, chunk)
                current_y -= 12

            return current_y
        
        try:

            if path_exists(dejasvusans_ttf):

                deja_font()

            else:

                wget.download(

                    url="https://github.com/prawnpdf/prawn/raw/master/data/fonts/DejaVuSans.ttf", 
                    out=dejasvusans_ttf
                
                    )

                if path_exists(dejasvusans_ttf):

                    deja_font()

        except Exception:

            font_information = (

                "An error occurred while downloading the DejaVuSans font !\n" 
                "Helvitica will be used instead."
            
                )

            showwarning(title=self.pyforensic_title, message=font_information)

            self.dejavusans_font = "Helvetica"

        report = canvas.Canvas(analysis_report, pagesize=letter)
        
        width, height = letter
        margin = 50

        y_position = height - margin

        report.setFont(self.dejavusans_font, 10)

        for text in results:

            lines = text.split("\n")

            for line in lines:

                y_position = pdf_position(line, y_position)

        if conclusion:

            report.showPage()
            report.setFont(self.dejavusans_font, 10)

            y_position = height - margin
            
            conclusion_spaced = conclusion.replace(". ", ".\n\n")
            lines = conclusion_spaced.split("\n")

            for line in lines:

                y_position = pdf_position(line, y_position)

        report.save()

    def analyze(self, directory_path): 

        results_pdf = []
        analyzer_tool = self
        
        self.malwarebazaar_quota = False
        self.virustotal_quota = False

        directory = Path(directory_path)

        def task(binary_path):

            if binary_path.suffix.lower() == ".exe":

                sha256_hash = hashlib.sha256()

                try:

                    with binary_path.open("rb") as binary_file:

                        for byte_block in iter(lambda: binary_file.read(4096), b""):

                            sha256_hash.update(byte_block)

                    malware_hash = sha256_hash.hexdigest()
                    no_informations = "N/A"

                    malwarebazaar_informations = analyzer_tool.malwarebazaar_data(
                        
                        binary_path.name, 
                        malware_hash, 
                        no_informations
                    
                        )
                    
                    virustotal_informations = analyzer_tool.virustotal_data(

                        malware_hash, 
                        no_informations
                    
                        )
                    
                    malwarebazaar_part = "\n".join(malwarebazaar_informations)
                    malwarebazaar_part = malwarebazaar_part.strip()
                    
                    virustotal_part = "\n".join(virustotal_informations)
                    
                    complete_results = malwarebazaar_part + "\n\n" + virustotal_part
                    
                    return complete_results

                except Exception:

                    return f"An error occurred while accessing the binary : {binary_path.name}"
            
            return None

        def result_thread(futures):

            first_result = True

            for future in as_completed(futures):

                analysis_result = future.result()

                if analysis_result:

                    output = analysis_result.strip()
                    results_pdf.append(output)

                    if not first_result:

                        yield "\n\n" + output

                    else:

                        yield output
                        first_result = False

                    time.sleep(1)

        def run_analysis():

            with ThreadPoolExecutor(max_workers=5) as executor:

                futures = {}

                for binary_file in directory.iterdir():

                    future = executor.submit(task, binary_file)
                    futures[future] = binary_file.name

                yield from result_thread(futures)

        yield from run_analysis()

        if results_pdf:

            showinfo(

                title=self.pyforensic_title, 
                message="All the results of the binary analysis have just been displayed !"
                
                )

            conclusion_ia = self.groq_conclusion(results_pdf)
            self.pdf_report(results_pdf, conclusion_ia)

            showinfo(

                title=self.pyforensic_title, 
                message="The analysis report has just been created !"
                
                )