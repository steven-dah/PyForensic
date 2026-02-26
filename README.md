PyForensic is forensic analysis software developed in Python.

It allows RAM memory to be extracted using the DumpIt acquisition tool, then analyzed using various plugins from the Volatility 3 framework.

The software also allows binaries within a directory to be analyzed, as well as IP addresses and URLs.

It has an MITM proxy, allowing you to intercept HTTP and HTTPS traffic in order to block malicious domains from a blacklist.

To function, PyForensic relies on several APIs, including MalwareBazaar, VirusTotal, AbuseIPDB, and Groq.

**Configuration:**

To use the software, you must enter your API keys in the .env file in the following format:

```
MALWAREBAZAAR_API=
VIRUSTOTAL_API=
ABUSEIPDB_API=
URLSCAN_API=
GROQ_API=
```

<img width="1143" height="655" alt="PyForensic" src="https://github.com/user-attachments/assets/0d3f18e1-7724-4ca4-8195-1f569a2fc579" />
