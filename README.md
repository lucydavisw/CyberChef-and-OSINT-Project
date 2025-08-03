# CyberChef-and-OSINT-Project

## Overview
This project demonstrates the use of CyberChef for decoding and decrypting various encoding schemes and explores Open Source Intelligence (OSINT) tools for vulnerability research. The lab includes practical tasks involving Base64, Hex, ROT13, XOR, Morse Code, and the use of threat databases such as CVE List, NVD, VirusTotal, and Microsoft Defender Threat Intelligence (formerly RiskIQ).

---

## Section 1: CyberChef Data Analysis and Decryption Activities

### 1.1 Base64 Decoding – Welcome Message (Step 4)
Decoded a Base64-encoded welcome message using CyberChef’s "From Base64" function. Highlighted how Base64 is used to obscure plaintext data such as usernames and passwords.

### 1.2 Hexadecimal Decoding – Recipe Output (Step 6)
Converted Hex-encoded data back to readable text using CyberChef. Discussed how Hex is used to represent binary data in forensics.

### 1.3 ROT13 Decryption – Caesar Cipher Variant (Step 8)
Used the ROT13 function in CyberChef to decode a simple substitution cipher. Explained how ROT13 is a Caesar cipher used for basic obfuscation.

### 1.4 XOR Brute Force Decryption – First Attempt (Step 10)
Applied an XOR brute force method to decrypt a message. The 12th key produced a meaningful partial message.

### 1.5 Morse Code Decoding – Signal Analysis (Step 11)
Decoded Morse code using CyberChef’s translation recipe. Demonstrated the conversion of encoded sequences into readable text.

### 1.6 Base64 Credential Decoding – Username and Password Extraction (Step 12)
Decoded a Base64 string that revealed login credentials:
- Username: `admin`
- Password: `str0ng!pw`

### 1.7 XOR Brute Force – Second Attempt and Observations (Step 13)
Performed XOR brute force again on another message. Found a partially readable message using the 48th key, noting some garbled output due to imperfect brute forcing.

---

## Section 2: Open Source Intelligence (OSINT) Research

### 2.1 CVE Entry Identification – Company and Registration Date (Step 2)
Identified that **CVE-2020-3693** is associated with **Qualcomm, Inc.**, registered on **2020-11-02**.

### 2.2 CVE Vulnerability Summary via NVD (Step 3)
Summarized vulnerability details from the NVD, highlighting a "use out of range pointer" issue in Qualcomm’s `qseecom`.

### 2.3 Proof of Microsoft Defender Threat Intelligence Membership (Step 9)
Provided visual confirmation of enrollment in the Microsoft Defender Threat Intelligence platform (formerly RiskIQ).

---

## Section 3: Summary and Tool Importance

### 3.1 The Role of CVE List and NVD
Explained how CVE and NVD help organizations track, prioritize, and patch known vulnerabilities using standardized IDs and severity ratings (CVSS).

### 3.2 The Role of VirusTotal
Described how VirusTotal enables multi-antivirus scanning for file or URL safety and supports malware detection during incident response.

### 3.3 The Role of RiskIQ / Microsoft Defender Threat Intelligence
Discussed how RiskIQ scans external digital assets for threats like phishing sites and exposed services, enabling proactive mitigation.

---

## Section 4: Conclusion
Summarized how CyberChef helps decode and analyze encrypted/encoded data, while OSINT tools like CVE List, NVD, VirusTotal, and RiskIQ support vulnerability management and threat intelligence.

---

## References
- [CVE List](https://cve.mitre.org/)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [VirusTotal](https://www.virustotal.com/)
- [Microsoft Defender Threat Intelligence (RiskIQ)](https://community.riskiq.com/)
- Goel & Mehtre (2015). Vulnerability assessment & penetration testing as a cyber defense technology.
- Santos et al. (2011). Collective Classification for Unknown Malware Detection.
- Scarfone & Mell (2009). Guide to CVSS.
