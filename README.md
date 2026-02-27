PyForensic is a forensic analysis tool developed in Python.

​It enables RAM extraction using the DumpIt acquisition tool, followed by analysis via various Volatility 3 framework plugins.

​The software also analyzes directory-based binaries, as well as IP addresses and URLs.

​It features a built-in MITM proxy to intercept HTTP/HTTPS traffic and block malicious domains found on a blacklist.

​To function, PyForensic integrates several APIs, including MalwareBazaar, VirusTotal, AbuseIPDB, and Groq.

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
