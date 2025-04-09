---
title: "Dreamhack Wargame"
description: "Dreamhack Wargame"
summary: "Dreamhack Wargame writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-10-18
draft: false
cover: ../../post/dreamhack/feature.png
authors:
  - winky
---

## Cookie

Bài này cho ta một trang web và file source sau :

![image](https://hackmd.io/_uploads/H1FVtUOQJg.png)

<details><summary>gen.py</summary>

```python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

users = {
    'guest': 'guest',
    'admin': FLAG
}

@app.route('/')
def index():
    username = request.cookies.get('username', None)
    if username:
        return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            resp.set_cookie('username', username)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'

app.run(host='0.0.0.0', port=8000)
```

</details>

Sau khi đọc source của bài thì cơ bản là trang web sẽ có 2 users là guest và admin và user sẽ dựa vào cookie của web nên ta sẽ đăng nhập vào và thay đổi 

![image](https://hackmd.io/_uploads/rJ_v9U_m1l.png)
![image](https://hackmd.io/_uploads/H1jO9IOXJl.png)

Sau khi đổi trường username trong cookie thì ta sẽ nhận được flag 

![image](https://hackmd.io/_uploads/rk2D98OXkx.png)

Flag : DH{7952074b69ee388ab45432737f9b0c56}

## Session
Bài này cho ta một trang web và file source sau :
![image](https://hackmd.io/_uploads/rJmisL_Xkg.png)

<details>
    <summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}


# this is our session storage
session_storage = {
}


@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # you cannot know admin's pw
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(32).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp
        return '<script>alert("wrong password");history.go(-1);</script>'


@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage


if __name__ == '__main__':
    import os
    # create admin sessionid and save it to our storage
    # and also you cannot reveal admin's sesseionid by brute forcing!!! haha
    session_storage[os.urandom(32).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)
```

</details>

Sau khi đọc source của bài thì trang web sẽ có 3 users và user sẽ dựa vào username và sessionid của web nên ta sẽ đăng nhập vào và thay đổi 

![image](https://hackmd.io/_uploads/BkRMhU_Q1l.png)
![image](https://hackmd.io/_uploads/Sk4S2IdmJg.png)

Để xem session id của admin ta sẽ vào endpoint /admin 

```python
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage
```

![image](https://hackmd.io/_uploads/Skm-0Lu7Jl.png)

Thay đổi và ta có được flag 

![image](https://hackmd.io/_uploads/SJZ4C8dX1x.png)

Flag : DH{8f3d86d1134c26fedf7c4c3ecd563aae3da98d5c}

## xss-1

Chúng ta được cho một trang web sau :

![image](https://hackmd.io/_uploads/HyFF9yKmJe.png)

và mình sẽ tập trung vào file app.py vì là phần backend của web 

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        # return str(e)
        return False
    driver.quit()
    return True


def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)
```
    
</details>

Sau khi đọc source thì mình có thể rút ra : 
* /vuln : là endpoint trả ra input của người dùng 
* /memo : để người dùng lưu lại note qua query param
* /flag : cho người dùng truy cập vào url được nhập sau đó được check bằng hàm check_xss

![image](https://hackmd.io/_uploads/BJhn5ytQJe.png)

Qua đó ta có ý tưởng sẽ sử dụng endpoint /flag để đưa vào đoạn script lấy cookie của user mà chứa flag 

```html
<script>window.location.href="/memo?memo="+document.cookie</script>
```

![image](https://hackmd.io/_uploads/r1-Xjyt7Jx.png)

Luồng của lỗ hổng : user nhập vào đoạn script trên -> hàm flag sẽ gọi hàm check_xss kèm với url là flag -> hàm check_xss sẽ gọi hàm read_url để tạo tab mới với flag trong cookie -> script sẽ lấy document.cookie và đưa vào /memo để lưu -> vào /memo để check kết quả 


![image](https://hackmd.io/_uploads/rkUVoyF71e.png)

Flag : flag=DH{2c01577e9542ec24d68ba0ffb846508e}

## xss-2 

Chúng ta được cho một trang web sau :

![image](https://hackmd.io/_uploads/ryOZ_mq7kx.png)


và mình sẽ tập trung vào file app.py vì là phần backend của web 

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        # return str(e)
        return False
    driver.quit()
    return True


def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")
def vuln():
    return render_template("vuln.html")


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)
```
    
</details>

Sau khi đọc source thì mình có thể rút ra : 
* /vuln : là endpoint trả ra input của người dùng 
* /memo : để người dùng lưu lại note qua query param
* /flag : cho người dùng truy cập vào url được nhập sau đó được check bằng hàm check_xss

![image](https://hackmd.io/_uploads/BJhn5ytQJe.png)

Qua đó ta có ý tưởng sẽ sử dụng endpoint /flag để đưa vào đoạn script lấy cookie của user mà chứa flag 
Nhưng ...
Khác với bài trước, bài này enđpoint /vuln sẽ đưa param của mình vào một trang web vuln.html và đoạn script sẽ không được thực thi như bài trước nên ta đổi payload thành như sau 

``` 
<img src="winky" onerror="location.href='/memo?memo='+document.cookie" />
```

![image](https://hackmd.io/_uploads/BkBTcX9m1e.png)

Luồng của lỗ hổng : user nhập vào đoạn script trên -> hàm flag sẽ gọi hàm check_xss kèm với url là flag -> hàm check_xss sẽ gọi hàm read_url để tạo tab mới với flag trong cookie -> script sẽ lấy document.cookie và đưa vào /memo để lưu -> vào /memo để check kết quả 


![image](https://hackmd.io/_uploads/By5A9m5Xyx.png)

Flag : flag=DH{3c01577e9542ec24d68ba0ffb846508f}


## csrf-1
Chúng ta được cho một trang web sau :

![image](https://hackmd.io/_uploads/BJ8P9_K7yl.png)

File source : 

<details>
<summary>app.py</summary>

```python
#!/usr/bin/python3
from flask import Flask, request, render_template
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        print(str(e))
        # return str(e)
        return False
    driver.quit()
    return True


def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "").lower()
    xss_filter = ["frame", "script", "on"]
    for _ in xss_filter:
        param = param.replace(_, "*")
    return param


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param", "")
        if not check_csrf(param):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", None)
    if text:
        memo_text += text
    return render_template("memo.html", memo=memo_text)


@app.route("/admin/notice_flag")
def admin_notice_flag():
    global memo_text
    if request.remote_addr != "127.0.0.1":
        return "Access Denied"
    if request.args.get("userid", "") != "admin":
        return "Access Denied 2"
    memo_text += f"[Notice] flag is {FLAG}\n"
    return "Ok"


app.run(host="0.0.0.0", port=8000)
```
    
</details>

Mình vào thử endpoint /admin/notice_flag và bị chặn 

![image](https://hackmd.io/_uploads/By5FcOKXye.png)

Mình nhận ra để vào thì request phải có host là 127.0.0.1 nghĩa là phải thông qua máy chủ của server đang host trang web này 

```python 
@app.route("/admin/notice_flag")
def admin_notice_flag():
    global memo_text
    if request.remote_addr != "127.0.0.1":
        return "Access Denied"
    if request.args.get("userid", "") != "admin":
        return "Access Denied 2"
    memo_text += f"[Notice] flag is {FLAG}\n"
    return "Ok"
```

Vì thế mình sẽ sử dụng payload sau : 

```html 
<img src='/admin/notice_flag?userid=admin'/>
```

![image](https://hackmd.io/_uploads/BkeJouYXJg.png)

Luồng của lỗ hổng : user nhập vào đoạn script trên -> hàm flag sẽ gọi hàm check_crsf -> hàm check_csrf sẽ gọi hàm read_url để tạo tab mới với host là 127.0.0.1 -> script sẽ vào được /notice/flag vì đúng host và userid là admin -> vào /memo để check kết quả

![image](https://hackmd.io/_uploads/HJE6hQcQyg.png)

Flag : DH{11a230801ad0b80d52b996cbe203e83d}

## csrf-2
Chúng ta được cho một trang web sau :

![image](https://hackmd.io/_uploads/SJeAyFYQJg.png)

File source : 

<details>
<summary>app.py</summary>

```python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"

users = {
    'guest': 'guest',
    'admin': FLAG
}

session_storage = {}

def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        print(str(e))
        # return str(e)
        return False
    driver.quit()
    return True


def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not an admin"}')


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "").lower()
    xss_filter = ["frame", "script", "on"]
    for _ in xss_filter:
        param = param.replace(_, "*")
    return param


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param", "")
        session_id = os.urandom(16).hex()
        session_storage[session_id] = 'admin'
        if not check_csrf(param, {"name":"sessionid", "value": session_id}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(8).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'


@app.route("/change_password")
def change_password():
    pw = request.args.get("pw", "")
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    users[username] = pw
    return 'Done'

app.run(host="0.0.0.0", port=8000)
```
    
</details>

Trang web yêu cầu chúng ta phải đăng nhập với các user là guest và admin

![image](https://hackmd.io/_uploads/SJeAyFYQJg.png)

![image](https://hackmd.io/_uploads/BJPWxttXkg.png)

Mình để ý vào hàm đổi mật khẩu 

```python
@app.route("/change_password")
def change_password():
    pw = request.args.get("pw", "")
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    users[username] = pw
    return 'Done'
```

Từ đó mình có ý tưởng sẽ sử dụng hàm này và endpoint /flag để đổi mật khẩu của user admin từ đó đọc được flag 

Vì thế mình sẽ sử dụng payload sau : 

```html 
<img src='change_password?pw=123' />
```

![image](https://hackmd.io/_uploads/rkqlZtFmJl.png)

Luồng của lỗ hổng : user nhập vào đoạn script trên -> hàm flag sẽ gọi hàm check_crsf -> hàm check_csrf sẽ gọi hàm read_url để tạo tab mới với host là 127.0.0.1 và user là admin -> script đổi mật khẩu của admin trên tab đó là 123 -> đăng nhập lại với user=admin và password=123 -> có flag 

![image](https://hackmd.io/_uploads/SyJzWFK7yl.png)

Flag : DH{c57d0dc12bb9ff023faf9a0e2b49e470a77271ef}




'union select null, null, null from ...

## command-injection-chatgpt

![image](https://hackmd.io/_uploads/HyAifuL4kg.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/env python3
import subprocess

from flask import Flask, request, render_template, redirect

from flag import FLAG

APP = Flask(__name__)


@APP.route('/')
def index():
    return render_template('index.html')


@APP.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 {host}'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')


if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8000)
```    

</details>

Bài này là điển hình của command injection
Mình sẽ thử sử dụng payload sau 
```1.1.1.1 && cat /etc/passwd``` 
thì cmd sẽ thành 
```ping -c 3 1.1.1.1 && cat /etc/passwd```
khi đó lệnh cat /etc/passwd sẽ được thực thi sau lệnh ping 

![image](https://hackmd.io/_uploads/HkK6G_8N1g.png)

Cuối cùng mình đổi lại file để đọc là flag.py và mình lấy được flag

```1.1.1.1 && cat flag.py```

![image](https://hackmd.io/_uploads/B1Y0z_LVyg.png)

Flag : DH{chatGPT_knows_what_the_ping_is}


## file-donwload-1

![image](https://hackmd.io/_uploads/S1fRTZ8VJg.png)

<details>
<summary>app.py</summary>

```python
#!/usr/bin/env python3
import os
import shutil

from flask import Flask, request, render_template, redirect

from flag import FLAG

APP = Flask(__name__)

UPLOAD_DIR = 'uploads'


@APP.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)


@APP.route('/upload', methods=['GET', 'POST'])
def upload_memo():
    if request.method == 'POST':
        filename = request.form.get('filename')
        content = request.form.get('content').encode('utf-8')

        if filename.find('..') != -1:
            return render_template('upload_result.html', data='bad characters,,')

        with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
            f.write(content)

        return redirect('/')

    return render_template('upload.html')


@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)


if __name__ == '__main__':
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)

    os.mkdir(UPLOAD_DIR)

    APP.run(host='0.0.0.0', port=8000)
```
    
</details>

Bài này sử dụng kĩ thuật path-traversal để đọc file
Mình thử tạo một note như sau 

![image](https://hackmd.io/_uploads/BJnkRb8NJe.png)

![image](https://hackmd.io/_uploads/SyHxRbLEkl.png)

Ở burpsuite khi đọc một note nó sẽ lấy file có name đã được tạo trước 

![image](https://hackmd.io/_uploads/By-GAW8E1e.png)

Nhận thấy file flag được import vào nên mình nghĩ nó đang nằm cũng hạng với app.py và ở ngoài thư mục file nên mình sẽ sử dụng payload sau để đọc flag

![image](https://hackmd.io/_uploads/HkPmCW8Ekg.png)

## path-traversal

![image](https://hackmd.io/_uploads/Hy1wTZLN1g.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template, abort
from functools import wraps
import requests
import os, json

users = {
    '0': {
        'userid': 'guest',
        'level': 1,
        'password': 'guest'
    },
    '1': {
        'userid': 'admin',
        'level': 9999,
        'password': 'admin'
    }
}

def internal_api(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.remote_addr == '127.0.0.1':
            return func(*args, **kwargs)
        else:
            abort(401)
    return decorated_view

app = Flask(__name__)
app.secret_key = os.urandom(32)
API_HOST = 'http://127.0.0.1:8000'

try:
    FLAG = open('./flag.txt', 'r').read() # Flag is here!!
except:
    FLAG = '[**FLAG**]'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    if request.method == 'GET':
        return render_template('get_info.html')
    elif request.method == 'POST':
        userid = request.form.get('userid', '')
        info = requests.get(f'{API_HOST}/api/user/{userid}').text
        return render_template('get_info.html', info=info)

@app.route('/api')
@internal_api
def api():
    return '/user/uid, /flag'

@app.route('/api/user/uid')
@internal_api
def get_flag(uid):
    try:
        info = users[uid]
    except:
        info = {}
    return json.dumps(info)

@app.route('/api/flag')
@internal_api
def flag():
    return FLAG

application = app # app.run(host='0.0.0.0', port=8000)
# Dockerfile
#     ENTRYPOINT ["uwsgi", "--socket", "0.0.0.0:8000", "--protocol=http", "--threads", "4", "--wsgi-file", "app.py"]
```
    
</details>

Khi mình cho userid là 0 thì trả ra user guest, mục tiêu của mình là đi đến hàm api/flag

![image](https://hackmd.io/_uploads/Sycv6bUVye.png)

Bài này sử dụng kĩ thuật SSPT (server side path traversal) vì ta không thể tự tiện truy cập vào endpoint flag bởi nó yêu cầu address của request là 127.0.0.1 tức là phải do máy chủ của web thực hiện

![image](https://hackmd.io/_uploads/SJpdaWUVyx.png)

Vì thế mình thực hiện đọc userid là ../flag, khi đó web sẽ gọi đến api /api/user/..id/flag -> /api/flag và ta đọc được flag

![image](https://hackmd.io/_uploads/BJ9t6ZU4yx.png)

Flag : DH{8a33bb6fe0a37522bdc8adb65116b2d4}
    
## Carve Party
    
![image](https://hackmd.io/_uploads/rkGJMMI41e.png)

<details>
<summary>jack-o-lantern.html</summary>
    
```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>do you want to build a jack-o-lantern?</title>
<style>
html, body { margin: 0; padding: 0; width: 100%; height: 100%; }
.jack { display: flex; flex-direction: column; align-items: center; justify-content: center; width: 100%; height: 100%; }
.jack svg { width: 50%; cursor: pointer; }
#jack-target { cursor: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='42' height='50' viewport='0 0 100 100' style='fill:black;font-size:25px;'><text y='50%'>🗡️</text></svg>") 16 0, auto; }
.tada { animation: 1s tada infinite; }
@keyframes tada {
  0% { transform: scale(1); }
  50% { transform: scale(1.1); }
  100% { transform: scale(1); }
}
</style>
</head>

<body>
<div class="jack">
  <h1>click the pumpkin to make a jack-o-lantern!</h1>
  <!-- openmoji.org -->
  <svg id="jack-target" viewBox="0 0 72 72" version="1.1" xmlns="http://www.w3.org/2000/svg">
    <path fill="#5C9E31" d="M47.8995,9.1325c0.0036-0.0902-0.0177-0.1854-0.02-0.277c-0.0012-0.1675-0.0161-0.3359-0.0366-0.5069 c-0.0126-0.0909-0.0187-0.1795-0.0366-0.2709c-0.0589-0.33-0.1401-0.6613-0.267-0.9896c-1.4448-3.7362-5.9587-4.9144-9.2682-2.8591 c-2.5414,1.5789-3.9725,4.4725-4.8703,7.2267c-0.8674,2.6562-1.3688,5.4905-1.5359,8.3c0.0057-0.0012,0.0123-0.002,0.0179-0.0032 c-0.0017,0.0278-0.0058,0.0557-0.0074,0.0834c0.8161-0.1688,1.7649-0.2942,2.8594-0.3484c0.0019-0.0265,0.006-0.053,0.0079-0.0795 c0.3639-0.0173,0.7436-0.0267,1.1403-0.0267c1.7114,0,3.1121,0.1713,4.2474,0.4241c-1.1245-2.8896-1.9282-6.282-1.0305-9.1633 c0.3867-1.2377,1.0952-2.5057,2.3122-3.1451c1.3619-0.7169,3.4476-0.1575,2.9586,1.75c-0.0953,0.373-0.4211,0.5609-0.616,0.8633 c-0.8978,1.3881,0.3412,2.3164,1.652,1.9849c1.6414-0.4139,2.4005-1.6262,2.4636-3.0253 C47.8793,9.0915,47.8909,9.1107,47.8995,9.1325z"/>
    <path fill="#F4AA41" d="M26.6422,19.7574c0.0035-0.0016,0.0068-0.0037,0.0103-0.0053c-0.1259-0.0449-0.25-0.0787-0.3753-0.1198 c-0.1509-0.0496-0.3019-0.1002-0.4519-0.1443c-0.1786-0.0525-0.3558-0.0975-0.533-0.1425 c-0.1506-0.0382-0.3013-0.0776-0.4509-0.1104c-0.1745-0.0383-0.3475-0.0692-0.5206-0.1003 c-0.1498-0.0269-0.2999-0.0552-0.4486-0.0767c-0.1706-0.0247-0.3394-0.0422-0.5086-0.0601 c-0.1487-0.0157-0.2977-0.0329-0.4453-0.0434c-0.1665-0.0119-0.3312-0.0167-0.4962-0.022c-0.147-0.0048-0.2944-0.011-0.4402-0.0107 c-0.1638,0.0004-0.3257,0.0078-0.4879,0.0145c-0.1439,0.006-0.288,0.0103-0.4306,0.0211c-0.161,0.0123-0.3202,0.0314-0.4795,0.0498 c-0.1407,0.0162-0.2819,0.0308-0.4213,0.0517c-0.1581,0.0237-0.3139,0.0543-0.4701,0.0839 c-0.1374,0.0261-0.2751,0.0503-0.411,0.0808c-0.1557,0.035-0.309,0.0767-0.4628,0.1175c-0.1331,0.0353-0.2668,0.0686-0.3984,0.1082 c-0.1534,0.0461-0.3042,0.0988-0.4555,0.1504c-0.1284,0.0438-0.2575,0.0856-0.3843,0.1334 c-0.1512,0.0569-0.2998,0.1205-0.4488,0.183c-0.1235,0.0518-0.2477,0.1014-0.3696,0.1569 c-0.1494,0.0679-0.2958,0.1423-0.4428,0.2157c-0.1176,0.0587-0.2362,0.1152-0.3523,0.1773 c-0.1473,0.0788-0.2915,0.1639-0.4362,0.248c-0.1122,0.0652-0.2254,0.1281-0.3361,0.1964 c-0.1448,0.0894-0.2864,0.1851-0.4285,0.2797c-0.1065,0.0709-0.2142,0.1396-0.3192,0.2134 c-0.1428,0.1003-0.2821,0.2067-0.4219,0.3123c-0.0999,0.0754-0.2012,0.1484-0.2996,0.2263 c-0.1401,0.1109-0.2764,0.2277-0.4134,0.3436c-0.0945,0.08-0.1905,0.1577-0.2835,0.24c-0.1364,0.1207-0.2689,0.2471-0.402,0.3727 c-0.0889,0.0839-0.1794,0.1655-0.2668,0.2515c-0.134,0.1318-0.2639,0.269-0.3943,0.4057c-0.082,0.0858-0.1656,0.1693-0.2461,0.257 c-0.1306,0.1422-0.2568,0.2896-0.3837,0.4365c-0.0761,0.0881-0.1541,0.1739-0.2287,0.2637 c-0.1258,0.1512-0.247,0.3074-0.3689,0.463c-0.071,0.0907-0.144,0.1792-0.2136,0.2714c-0.1213,0.1606-0.2376,0.3259-0.3546,0.4906 c-0.0653,0.0919-0.1328,0.1818-0.1967,0.2751c-0.1155,0.1685-0.226,0.3414-0.337,0.5138 c-0.0607,0.0942-0.1237,0.1865-0.1831,0.2819c-0.1089,0.175-0.2125,0.3542-0.3168,0.533 c-0.0565,0.0969-0.1155,0.1919-0.1706,0.2898c-0.1023,0.1816-0.1989,0.3669-0.2965,0.5518 c-0.0519,0.0984-0.1064,0.1952-0.1569,0.2946c-0.0964,0.1894-0.1867,0.3821-0.278,0.5746 c-0.0465,0.0981-0.0957,0.1948-0.1409,0.2936c-0.0875,0.1917-0.169,0.3862-0.2514,0.5805 c-0.0438,0.1032-0.0904,0.205-0.1327,0.3089c-0.0831,0.2042-0.16,0.411-0.2374,0.6177c-0.0357,0.0952-0.0742,0.189-0.1087,0.2847 c-0.0733,0.2036-0.1399,0.4095-0.2076,0.6152c-0.0338,0.1027-0.0707,0.2042-0.1031,0.3073 c-0.0641,0.2042-0.1213,0.4104-0.1798,0.6162c-0.0298,0.105-0.0629,0.209-0.0912,0.3145c-0.0581,0.2161-0.1092,0.4339-0.161,0.6514 c-0.023,0.0966-0.0494,0.1924-0.0711,0.2893c-0.0527,0.2349-0.098,0.4709-0.1432,0.7069 c-0.0154,0.0805-0.0342,0.1605-0.0487,0.2411c-0.051,0.2827-0.0947,0.5662-0.1347,0.8497 c-0.0048,0.0343-0.0116,0.0685-0.0163,0.1028c-0.3012,2.2099-0.2696,4.4514,0.076,6.6451 c0.1729,1.0981,0.4187,2.1852,0.7521,3.2487c0.4583,1.4606,1.0642,2.8831,1.7966,4.2331c0.6502,1.1984,1.3989,2.3402,2.2521,3.3903 c0.0835,0.1027,0.1737,0.1989,0.259,0.2999c0.1797,0.2126,0.3576,0.4269,0.5455,0.6316c0.0008,0.0009,0.0015,0.0016,0.0023,0.0024 c0.2523,0.2747,0.5026,0.5352,0.7516,0.787c0.0829,0.0839,0.165,0.1624,0.2476,0.2438c0.1679,0.1655,0.3353,0.3282,0.5015,0.4839 c0.0938,0.0877,0.1868,0.1724,0.28,0.257c0.1547,0.1404,0.3085,0.2768,0.4616,0.4089c0.0943,0.0813,0.1883,0.1623,0.2819,0.2404 c0.158,0.1319,0.3145,0.2576,0.4708,0.3809c0.083,0.0656,0.1665,0.1335,0.2491,0.1966c0.2084,0.1595,0.4152,0.3112,0.6203,0.4559 c0.0272,0.0192,0.055,0.0409,0.0822,0.0599c0.2303,0.1606,0.4578,0.3104,0.6835,0.4533c0.0784,0.0496,0.1554,0.0947,0.2332,0.1422 c0.1491,0.0911,0.2977,0.1804,0.4447,0.264c0.0888,0.0506,0.1768,0.0985,0.2649,0.1464c0.1353,0.0737,0.2697,0.1446,0.4031,0.2122 c0.0882,0.0447,0.1761,0.0889,0.2634,0.131c0.136,0.0656,0.2705,0.127,0.4043,0.1865c0.079,0.0352,0.1584,0.0719,0.2367,0.105 c0.1684,0.0712,0.3347,0.1367,0.4996,0.1988c0.0403,0.0152,0.0815,0.0329,0.1216,0.0475c0.2014,0.0737,0.3996,0.1396,0.5952,0.2003 c0.0689,0.0214,0.1362,0.0394,0.2044,0.0592c0.1293,0.0377,0.2579,0.0742,0.3846,0.1066c0.0772,0.0197,0.1531,0.0375,0.2293,0.0553 c0.1164,0.0272,0.2316,0.0527,0.3457,0.0757c0.0753,0.0152,0.1501,0.03,0.2243,0.0433c0.1163,0.021,0.2306,0.0392,0.3442,0.0561 c0.0658,0.0098,0.1322,0.0206,0.1972,0.0291c0.14,0.0182,0.2772,0.0324,0.4129,0.0447c0.0353,0.0032,0.0719,0.0081,0.1069,0.0109 c0.1683,0.0135,0.3325,0.0222,0.4938,0.0273c0.0517,0.0016,0.1014,0.0013,0.1524,0.0021c0.111,0.0019,0.2208,0.0028,0.3282,0.0012 c0.058-0.0009,0.1144-0.0029,0.1713-0.0048c0.0989-0.0033,0.1963-0.0076,0.2919-0.0136c0.0549-0.0034,0.1092-0.0071,0.1631-0.0114 c0.0978-0.0078,0.1932-0.0172,0.2873-0.0275c0.0454-0.0049,0.0914-0.0094,0.1358-0.015c0.1164-0.0145,0.2295-0.0309,0.3399-0.0487 c0.0189-0.0031,0.039-0.0054,0.0577-0.0086c0.1305-0.0219,0.2561-0.046,0.3778-0.0716c0.0274-0.0058,0.053-0.0122,0.08-0.0181 c0.0928-0.0204,0.1835-0.0415,0.2709-0.0636c0.0342-0.0087,0.067-0.0175,0.1003-0.0264c0.0787-0.0209,0.1552-0.0421,0.2292-0.064 c0.03-0.0089,0.0594-0.0175,0.0885-0.0265c0.0775-0.0237,0.1517-0.0477,0.2235-0.0719c0.0207-0.007,0.0419-0.0137,0.062-0.0208 c0.1862-0.0645,0.3523-0.129,0.4965-0.1904c0.0011-0.0005,0.002-0.0009,0.0031-0.0014c0.0535-0.0228,0.1055-0.0453,0.153-0.0669 c0,0-0.0007-0.0005-0.001-0.0007c0.3469-0.1577,0.5346-0.278,0.5346-0.278c1.4692,1.4635,7.6696,1.7152,8.0888,1.7307 c0.0154,0.0005,0.0293,0.0005,0.0447,0c0.4192-0.0154,6.6196-0.2672,8.0888-1.7307c0,0,6.8438,4.4366,15.5886-5.0859 c7.0378-7.0443,7.9-20.5231,2.0165-28.6674c-0.5543-0.7675-1.1686-1.4874-1.8432-2.1503 c-1.0616-1.0431-2.2445-1.9655-3.5286-2.7019c-3.6327-2.0837-7.8248-2.3765-11.7263-0.8917c0,0-2.0279-2.4888-8.6181-2.4888 s-8.6181,2.4888-8.6181,2.4888C26.8595,19.8278,26.7515,19.7963,26.6422,19.7574"/>
    <path fill="#E27022" d="M44.5882,59.6454c1.7503,0.8029,7.6702,2.5917,14.9042-5.3642c2.1951-2.4146,3.8261-5.4041,4.805-8.5551 c0.9897-3.1884,1.2669-6.5781,0.8197-9.8944c-1.3646-10.1149-9.7316-19.8646-20.2419-16.0795 c5.7584,2.7111,9.8136,9.4387,10.743,16.3279c0.4653,3.4475,0.176,6.9711-0.8522,10.2849 c-1.0174,3.2764-2.7123,6.3828-4.9942,8.8938C47.949,57.2634,46.207,58.6726,44.5882,59.6454z"/>
    <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M39.4,17.6598c-0.68-2.34-0.98-4.83-0.3-7.02c0.39-1.24,1.1-2.5,2.31-3.14c1.36-0.72,3.45-0.16,2.96,1.75 c-0.09,0.37-0.42,0.56-0.62,0.86c-0.89,1.39,0.35,2.32,1.66,1.99c1.64-0.42,2.4-1.63,2.46-3.03c0.01,0.02,0.02,0.04,0.03,0.06 c0-0.09-0.02-0.18-0.02-0.27c0-0.17-0.02-0.34-0.04-0.51c-0.01-0.09-0.02-0.18-0.03-0.27c-0.06-0.33-0.14-0.66-0.27-0.99 c-1.45-3.74-5.96-4.92-9.27-2.86c-2.54,1.58-3.97,4.47-4.87,7.23c-0.66,2.01-1.11,4.13-1.36,6.26"/>
    <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M7.1349,33.9318c-0.0522,0.2349-0.097,0.4709-0.1418,0.7069c-0.0153,0.0805-0.0338,0.1605-0.0482,0.2411 c-0.0505,0.2827-0.0938,0.5662-0.1334,0.8497C6.8067,35.7638,6.8,35.798,6.7954,35.8323 c-0.2982,2.2099-0.2669,4.4514,0.0752,6.6451c0.1711,1.0981,0.4145,2.1852,0.7446,3.2487 c0.4537,1.4606,1.0535,2.8831,1.7787,4.2331c0.6437,1.1984,1.3849,2.3402,2.2296,3.3903c0.0826,0.1027,0.172,0.1989,0.2564,0.2999 c0.1779,0.2126,0.354,0.4269,0.54,0.6316c0.0008,0.0009,0.0015,0.0016,0.0023,0.0024c0.2498,0.2747,0.4976,0.5352,0.7441,0.787 c0.0821,0.0839,0.1634,0.1624,0.2451,0.2438c0.1662,0.1655,0.332,0.3282,0.4965,0.4839c0.0928,0.0877,0.1849,0.1724,0.2772,0.257 c0.1531,0.1404,0.3054,0.2768,0.457,0.4089c0.0933,0.0813,0.1864,0.1623,0.2791,0.2404c0.1564,0.1319,0.3114,0.2576,0.4661,0.3809 c0.0822,0.0656,0.1649,0.1335,0.2466,0.1966c0.2064,0.1595,0.4111,0.3112,0.6141,0.4559c0.027,0.0192,0.0544,0.0409,0.0814,0.0599 c0.228,0.1606,0.4532,0.3104,0.6767,0.4533c0.0776,0.0496,0.1539,0.0947,0.2309,0.1422c0.1476,0.0911,0.2947,0.1804,0.4402,0.264 c0.088,0.0506,0.175,0.0985,0.2622,0.1464c0.134,0.0737,0.267,0.1446,0.399,0.2122c0.0873,0.0447,0.1744,0.0889,0.2608,0.131 c0.1346,0.0656,0.2678,0.127,0.4003,0.1865c0.0782,0.0352,0.1569,0.0719,0.2343,0.105c0.1667,0.0712,0.3314,0.1367,0.4946,0.1988 c0.0399,0.0152,0.0807,0.0329,0.1204,0.0475c0.1994,0.0737,0.3956,0.1396,0.5893,0.2003c0.0682,0.0214,0.1348,0.0394,0.2023,0.0592 c0.1281,0.0377,0.2554,0.0742,0.3807,0.1066c0.0764,0.0197,0.1516,0.0375,0.2271,0.0553c0.1152,0.0272,0.2293,0.0527,0.3422,0.0757 c0.0745,0.0152,0.1486,0.03,0.222,0.0433c0.1151,0.021,0.2283,0.0392,0.3408,0.0561c0.0652,0.0098,0.1309,0.0206,0.1952,0.0291 c0.1386,0.0182,0.2744,0.0324,0.4088,0.0447c0.035,0.0032,0.0712,0.0081,0.1058,0.0109c0.1666,0.0135,0.3292,0.0222,0.4889,0.0273 c0.0511,0.0016,0.1004,0.0013,0.1509,0.0021c0.1099,0.0019,0.2186,0.0028,0.3249,0.0012c0.0574-0.0009,0.1133-0.0029,0.1696-0.0048 c0.0979-0.0033,0.1943-0.0076,0.289-0.0136c0.0543-0.0034,0.1082-0.0071,0.1614-0.0114c0.0968-0.0078,0.1912-0.0172,0.2844-0.0275 c0.0449-0.0049,0.0905-0.0094,0.1345-0.015c0.1152-0.0145,0.2272-0.0309,0.3365-0.0487c0.0187-0.0031,0.0386-0.0054,0.0571-0.0086 c0.1292-0.0219,0.2535-0.046,0.374-0.0716c0.0272-0.0058,0.0524-0.0122,0.0792-0.0181c0.0919-0.0204,0.1817-0.0415,0.2682-0.0636 c0.0338-0.0087,0.0663-0.0175,0.0993-0.0264c0.0779-0.0209,0.1536-0.0421,0.2269-0.064c0.0297-0.0089,0.0588-0.0175,0.0876-0.0265 c0.0767-0.0237,0.1502-0.0477,0.2213-0.0719c0.0204-0.007,0.0414-0.0137,0.0614-0.0208c0.1843-0.0645,0.3488-0.129,0.4916-0.1904 c0.0011-0.0005,0.002-0.0009,0.0031-0.0014c0.053-0.0228,0.1045-0.0453,0.1515-0.0669c-0.0003-0.0002-0.0007-0.0005-0.001-0.0007 c0.3434-0.1577,0.5293-0.278,0.5293-0.278c1.4545,1.4635,7.593,1.7152,8.0081,1.7307c0.0152,0.0005,0.0291,0.0005,0.0443,0 c0.415-0.0154,6.5535-0.2672,8.0081-1.7307c0,0,6.7755,4.4366,15.4329-5.0859c6.9675-7.0443,7.8211-20.5231,1.9964-28.6674 c-0.5488-0.7675-1.1569-1.4874-1.8248-2.1503c-1.051-1.0431-2.222-1.9655-3.4933-2.7019 c-3.5964-2.0837-7.7466-2.3765-11.6092-0.8917c0,0-2.0076-2.4888-8.532-2.4888s-8.532,2.4888-8.532,2.4888 c-0.1086-0.0417-0.2155-0.0732-0.3237-0.1121"/>
    <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M27.0273,19.7574c0.0035-0.0016,0.0067-0.0037,0.0102-0.0053c-0.1246-0.0449-0.2475-0.0787-0.3715-0.1198 c-0.1494-0.0496-0.2989-0.1002-0.4474-0.1443c-0.1768-0.0525-0.3522-0.0975-0.5277-0.1425 c-0.1491-0.0382-0.2983-0.0776-0.4464-0.1104c-0.1727-0.0383-0.344-0.0692-0.5154-0.1003 c-0.1483-0.0269-0.2969-0.0552-0.4442-0.0767c-0.1689-0.0247-0.3361-0.0422-0.5035-0.0601 c-0.1472-0.0157-0.2947-0.0329-0.4409-0.0434c-0.1648-0.0119-0.3279-0.0167-0.4912-0.022 c-0.1456-0.0048-0.2914-0.011-0.4358-0.0107c-0.1622,0.0004-0.3224,0.0078-0.483,0.0145c-0.1425,0.006-0.2852,0.0103-0.4263,0.0211 c-0.1594,0.0123-0.317,0.0314-0.4747,0.0498c-0.1393,0.0162-0.2791,0.0308-0.4171,0.0517 c-0.1565,0.0237-0.3108,0.0543-0.4655,0.0839c-0.136,0.0261-0.2724,0.0503-0.4069,0.0808 c-0.1541,0.035-0.3059,0.0767-0.4581,0.1175c-0.1318,0.0353-0.2641,0.0686-0.3945,0.1082 c-0.1519,0.0461-0.3011,0.0988-0.451,0.1504c-0.1271,0.0438-0.2549,0.0856-0.3805,0.1334 c-0.1497,0.0569-0.2968,0.1205-0.4443,0.183c-0.1223,0.0518-0.2452,0.1014-0.3659,0.1569 c-0.1479,0.0679-0.2928,0.1423-0.4384,0.2157c-0.1165,0.0587-0.2339,0.1152-0.3488,0.1773 c-0.1458,0.0788-0.2886,0.1639-0.4318,0.248c-0.1111,0.0652-0.2231,0.1281-0.3327,0.1964 c-0.1434,0.0894-0.2835,0.1851-0.4242,0.2797c-0.1055,0.0709-0.2121,0.1396-0.316,0.2134 c-0.1414,0.1003-0.2792,0.2067-0.4177,0.3123c-0.0989,0.0754-0.1992,0.1484-0.2966,0.2263 c-0.1387,0.1109-0.2736,0.2277-0.4092,0.3436c-0.0936,0.08-0.1886,0.1577-0.2807,0.24c-0.135,0.1207-0.2662,0.2471-0.3979,0.3727 c-0.088,0.0839-0.1776,0.1655-0.2642,0.2515c-0.1327,0.1318-0.2612,0.269-0.3904,0.4057c-0.0812,0.0858-0.1639,0.1693-0.2437,0.257 c-0.1293,0.1422-0.2543,0.2896-0.3798,0.4365c-0.0754,0.0881-0.1525,0.1739-0.2264,0.2637"/>
    <g id="jack-mouth" style="opacity: 0;">
      <path fill="#FCEA2B" d="M20,48c0,0,15,10,32,0C52,48,36,68,20,48z"/>
      <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M20,48c0,0,15,10,32,0C52,48,36,68,20,48z"/>
    </g>
    <g id="jack-nose" style="opacity: 0;">
      <polygon fill="#FCEA2B" points="35.896,47.9282 34.1847,44.9641 32.4734,42 35.896,42 39.3187,42 37.6073,44.9641"/>
      <polygon fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" points="35.896,47.9282 34.1847,44.9641 32.4734,42 35.896,42 39.3187,42 37.6073,44.9641"/>
    </g>
    <g id="jack-right" style="opacity: 0;">
      <path fill="#FCEA2B" d="M48.974,37.8449c2.5901-0.9575,3.9136-3.8335,2.956-6.4235l-9.3796,3.4675 C43.508,37.479,46.3839,38.8024,48.974,37.8449z"/>
      <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M48.974,37.8449c2.5901-0.9575,3.9136-3.8335,2.956-6.4235l-9.3796,3.4675C43.508,37.479,46.3839,38.8024,48.974,37.8449z"/>
    </g>
    <g id="jack-left" style="opacity: 0;">
      <path fill="#FCEA2B" d="M22.818,37.8449c-2.5901-0.9575-3.9136-3.8335-2.956-6.4235l9.3796,3.4675 C28.2841,37.479,25.4081,38.8024,22.818,37.8449z"/>
      <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M22.818,37.8449c-2.5901-0.9575-3.9136-3.8335-2.956-6.4235l9.3796,3.4675C28.2841,37.479,25.4081,38.8024,22.818,37.8449z"/>
    </g>
  </svg>
  <canvas width=720>
    <div class="txtStyle"></div>
</canvas>
  <p><span id="clicks">10000</span> more clicks to go!</p>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js" integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg==" crossorigin="anonymous"></script>
<script>
var pumpkin = [ 124, 112, 59, 73, 167, 100, 105, 75, 59, 23, 16, 181, 165, 104, 43, 49, 118, 71, 112, 169, 43, 53 ];
var counter = 0;
var pie = 1;

function make() {
  if (0 < counter && counter <= 1000) {
    $('#jack-nose').css('opacity', (counter) + '%');
  }
  else if (1000 < counter && counter <= 3000) {
    $('#jack-left').css('opacity', (counter - 1000) / 2 + '%');
  }
  else if (3000 < counter && counter <= 5000) {
    $('#jack-right').css('opacity', (counter - 3000) / 2 + '%');
  }
  else if (5000 < counter && counter <= 10000) {
    $('#jack-mouth').css('opacity', (counter - 5000) / 5 + '%');
  }

  if (10000 < counter) {
    $('#jack-target').addClass('tada');
    var ctx = document.querySelector("canvas").getContext("2d"),
    dashLen = 220, dashOffset = dashLen, speed = 20,
    txt = pumpkin.map(x=>String.fromCharCode(x)).join(''), x = 30, i = 0;

    ctx.font = "50px Comic Sans MS, cursive, TSCu_Comic, sans-serif"; 
    ctx.lineWidth = 5; ctx.lineJoin = "round"; ctx.globalAlpha = 2/3;
    ctx.strokeStyle = ctx.fillStyle = "#1f2f90";

    (function loop() {
      ctx.clearRect(x, 0, 60, 150);
      ctx.setLineDash([dashLen - dashOffset, dashOffset - speed]); // create a long dash mask
      dashOffset -= speed;                                         // reduce dash length
      ctx.strokeText(txt[i], x, 90);                               // stroke letter

      if (dashOffset > 0) requestAnimationFrame(loop);             // animate
      else {
        ctx.fillText(txt[i], x, 90);                               // fill final letter
        dashOffset = dashLen;                                      // prep next char
        x += ctx.measureText(txt[i++]).width + ctx.lineWidth * Math.random();
        ctx.setTransform(1, 0, 0, 1, 0, 3 * Math.random());        // random y-delta
        ctx.rotate(Math.random() * 0.005);                         // random rotation
        if (i < txt.length) requestAnimationFrame(loop);
      }
    })();
  }
  else {
    $('#clicks').text(10000 - counter);
  }
}

$(function() {
  $('#jack-target').click(function () {
    counter += 1;
    if (counter <= 10000 && counter % 100 == 0) {
      for (var i = 0; i < pumpkin.length; i++) {
        pumpkin[i] ^= pie;
        pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
      }
    }
    make();
  });
});
</script>
</body>
</html>
```
    
</details>

Trang web yêu cầu mình nhấn vào quả bí 10000 lần nên mình sử dụng đoạn script sau để tăng tiến độ
```for(let i=0;i\<9999;i++)('\#jack-target').click()```

![image](https://hackmd.io/_uploads/SkqXzM84kx.png)

Khi ấn đủ 10000 thì web cho ta flag

![image](https://hackmd.io/_uploads/Sk3rGMIEkx.png)

Flag : DH{I_lik3_pumpk1n_pi3}
                     
## PHPreg

![image](https://hackmd.io/_uploads/r1hJtGU4kl.png)

<details>
<summary>step2.php</summary>
    
```php
<html>
<head>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
<title>PHPreg</title>
</head>
<body>
  <!-- Fixed navbar -->
  <nav class="navbar navbar-default navbar-fixed-top">
    <div class="container">
      <div class="navbar-header">
        <a class="navbar-brand" href="/">PHPreg</a>
      </div>
      <div id="navbar">
        <ul class="nav navbar-nav">
          <li><a href="/">Step 1</a></li>
          <li><a href="/step2.php">Step 2</a></li>
        </ul>
      </div><!--/.nav-collapse -->
    </div>
  </nav><br/><br/><br/>
  <div class="container">
    <div class="box">
      <!-- PHP code -->
      <?php
          // POST request
          if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $input_name = $_POST["input1"] ? $_POST["input1"] : "";
            $input_pw = $_POST["input2"] ? $_POST["input2"] : "";

            // pw filtering
            if (preg_match("/[a-zA-Z]/", $input_pw)) {
              echo "alphabet in the pw :(";
            }
            else{
              $name = preg_replace("/nyang/i", "", $input_name);
              $pw = preg_replace("/\d*\@\d{2,3}(31)+[^0-8\"]\!/", "d4y0r50ng", $input_pw);
              
              if ($name === "dnyang0310" && $pw === "d4y0r50ng+1+13") {
                echo '<h4>Step 2 : Almost done...</h4><div class="door_box"><div class="door_black"></div><div class="door"><div class="door_cir"></div></div></div>';

                $cmd = $_POST["cmd"] ? $_POST["cmd"] : "";

                if ($cmd === "") {
                  echo '
                        <p><form method="post" action="/step2.php">
                            <input type="hidden" name="input1" value="'.$input_name.'">
                            <input type="hidden" name="input2" value="'.$input_pw.'">
                            <input type="text" placeholder="Command" name="cmd">
                            <input type="submit" value="제출"><br/><br/>
                        </form></p>
                  ';
                }
                // cmd filtering
                else if (preg_match("/flag/i", $cmd)) {
                  echo "<pre>Error!</pre>";
                }
                else{
                  echo "<pre>--Output--\n";
                  system($cmd);
                  echo "</pre>";
                }
              }
              else{
                echo "Wrong nickname or pw";
              }
            }
          }
          // GET request
          else{
            echo "Not GET request";
          }
      ?>
    </div>
  </div>

  <style type="text/css">
    h4 {
      color: rgb(84, 84, 84);
    }
    .box{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    pre {
      width: 80%;
    }
    .door_box {
      position: relative;
      width: 240px;
      height: 180px;
      margin: 20px 0px;
    }
    .door_black {
      position: absolute;
      width: 140px;
      height: 180px;
      background-color: black;
      border-radius: 10px;
      right:0px;
    }
    .door {
      z-index: 2;
      position: absolute;
      width: 140px;
      height: 180px;
      background-color: #b9abf7;
      border-radius: 10px;
      right: 100px;
    }
    .door_cir{
      z-index: 3;
      position: absolute;
      border-radius: 50%;
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255, 222, 113, 0.873);
      background-color: #ffea98;
      top: calc( 180px / 2 - 10px );
      right: 10px;
    }
  </style>
</body>
</html>
```
    
</details>

Đầu tiên để bypass được step1 thì ta phân tích 2 biến sau
```$name = preg_replace("/nyang/i", "", $input_name);```
```$pw = preg_replace("/\d*\@\d{2,3}(31)+[^0-8\"]\!/", "d4y0r50ng", $input_pw);```

và điều kiện sau khi filter là ```$name === "dnyang0310" && $pw === "d4y0r50ng+1+13"```

Vì thế mình thử gen ra nickname và password như sau
Nickname : dnynyangang0310
Password : 1@11319!+1+13

![image](https://hackmd.io/_uploads/SJ-PKMUV1l.png)

Sau khi pass được step2 thì trang web yêu cầu nhập linux command để thực thi nhưng lại thay thế xoá đi chữ flag trong lệnh

![image](https://hackmd.io/_uploads/S1vdYfU4Jl.png)

Vì thế mình sử dụng payload sau để lấy flag
CMD : cat ../dream/fla*

![image](https://hackmd.io/_uploads/rJXcKfIVye.png)

Flag : DH{ad866c64dabaf30136e22d3de2980d24c4da617b9d706f81d10a1bc97d0ab6f6}

## session-2

![image](https://hackmd.io/_uploads/r10Kpf8Eke.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}

session_storage = {
}

@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(4).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'

if __name__ == '__main__':
    import os
    session_storage[os.urandom(1).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)
```    

</details>

Đầu tiên mình thử đăng nhập vào bằng user guest

![image](https://hackmd.io/_uploads/S1M6aM8Ekl.png)

Xem qua code thì hình như session của admin là một bytes được chuyển sang hex
**session_storage[os.urandom(1).hex()] = 'admin'**

Nên mình thử gen ra các giá trị của hàm trên

![image](https://hackmd.io/_uploads/SkxbCfLEJx.png)

```python
for i in range(0xff+1):
	data = bytes([i]).hex()
	print(data)
```



![image](https://hackmd.io/_uploads/Hk6TAzLVye.png)

Mình sử dụng intruder cửa burpsuite để kiểm tra các giá trị trên

![image](https://hackmd.io/_uploads/HJZzAMIE1g.png)

sau khi chạy xong thì mình thấy session 28 sẽ có keyword flag
đổi lại session và ta có flag

![image](https://hackmd.io/_uploads/rk8mCfLVJx.png)

Flag : DH{73b3a0ebf47fd6f68ce623853c1d4f138ad91712}


## web-misconf-1

![image](https://hackmd.io/_uploads/BJAQem84ke.png)

Trang web cho mình một file setting và mình thấy có username và password của admin

![image](https://hackmd.io/_uploads/HJZrxQU41x.png)

Đăng nhập vào và kiếm được flag ở trưởng org name

![image](https://hackmd.io/_uploads/SkRPe7IVJe.png)

Flag : DH{default_account_is very dangerous}

## simple-web-request

![image](https://hackmd.io/_uploads/SklttmL41l.png)

![image](https://hackmd.io/_uploads/HJCFt7LN1g.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
import os
from flask import Flask, request, render_template, redirect, url_for
import sys

app = Flask(__name__)

try: 
    # flag is here!
    FLAG = open("./flag.txt", "r").read()      
except:
    FLAG = "[**FLAG**]"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/step1", methods=["GET", "POST"])
def step1():

    #### 풀이와 관계없는 치팅 방지 코드
    global step1_num
    step1_num = int.from_bytes(os.urandom(16), sys.byteorder)
    ####

    if request.method == "GET":
        prm1 = request.args.get("param", "")
        prm2 = request.args.get("param2", "")
        step1_text = "param : " + prm1 + "\nparam2 : " + prm2 + "\n"
        if prm1 == "getget" and prm2 == "rerequest":
            return redirect(url_for("step2", prev_step_num = step1_num))
        return render_template("step1.html", text = step1_text)
    else: 
        return render_template("step1.html", text = "Not POST")


@app.route("/step2", methods=["GET", "POST"])
def step2():
    if request.method == "GET":

    #### 풀이와 관계없는 치팅 방지 코드
        if request.args.get("prev_step_num"):
            try:
                prev_step_num = request.args.get("prev_step_num")
                if prev_step_num == str(step1_num):
                    global step2_num
                    step2_num = int.from_bytes(os.urandom(16), sys.byteorder)
                    return render_template("step2.html", prev_step_num = step1_num, hidden_num = step2_num)
            except:
                return render_template("step2.html", text="Not yet")
        return render_template("step2.html", text="Not yet")
    ####

    else: 
        return render_template("step2.html", text="Not POST")

    
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html", flag_txt="Not yet")
    else:

        #### 풀이와 관계없는 치팅 방지 코드
        prev_step_num = request.form.get("check", "")
        try:
            if prev_step_num == str(step2_num):
        ####

                prm1 = request.form.get("param", "")
                prm2 = request.form.get("param2", "")
                if prm1 == "pooost" and prm2 == "requeeest":
                    return render_template("flag.html", flag_txt=FLAG)
                else:
                    return redirect(url_for("step2", prev_step_num = str(step1_num)))
            return render_template("flag.html", flag_txt="Not yet")
        except:
            return render_template("flag.html", flag_txt="Not yet")
            

app.run(host="0.0.0.0", port=8000)
```
    
</details>

Sau khi đoc source thì mình có param1 và param2 để bypass step1

![image](https://hackmd.io/_uploads/SkClqm8NJx.png)

![image](https://hackmd.io/_uploads/By_yc78E1x.png)

Ở step 2 mình cũng có param1 và param2, điền vào và có flag

![image](https://hackmd.io/_uploads/rJNx9784yg.png)

![image](https://hackmd.io/_uploads/BJWfqQUVkx.png)

Flag : DH{c46b414ddba26adfa4606c59655bda0a18fbe260606b042b52d865e0160eea0e}

## php7cmp4re

![image](https://hackmd.io/_uploads/SyO5DDLVJe.png)

![image](https://hackmd.io/_uploads/rkLoPwLEJx.png)

Đầu tiên mình xem qua source code và thấy điều kiện của input_1 là 

```if($input_1 < "8" && $input_1 < "7.A" && $input_1 > "7.9")```

Vì thế mình có thể đoán $input_1 là "7.<char>" với "9" < char < "A" theo bảng ASCII nên mình chọn char là ":" -> $input_1 = 7.:

Tiếp theo là điều kiện của $input_2 như sau :

```if($input_2 < 74 && $input_2 > "74")```

Trong php nếu ta nhập vào một string bao gồm số, khi so sánh sẽ cố lấy các chữ số đầu tiên để so sánh ví dụ như khi so sánh 74 với "7a" thì nó sẽ so sánh 74 với 7 do a không phải số, mặt khác "7a" lại lớn hơn "74" theo ascii nên đây là $input_2 của mình

![image](https://hackmd.io/_uploads/S1Et_wLEkg.png)

Điền vào và có được flag

![image](https://hackmd.io/_uploads/r119OPINye.png)

Flag : DH{81df5f707394347306c1ce2693601349407013aedbf79ae8d97a502c3d138bfe}

## Flying chars

![image](https://hackmd.io/_uploads/S1Q55DU4Je.png)

Trang web cho ta các hình ảnh bay tứ tung nhưng mình nhìn khá giống chữ

![image](https://hackmd.io/_uploads/SkEiqwIVJx.png)

Sau khi xem các ảnh và sắp xếp lại thì mình thu được flag

![image](https://hackmd.io/_uploads/B1pjcvLE1x.png)

![image](https://hackmd.io/_uploads/SkL2cvLVkx.png)

![image](https://hackmd.io/_uploads/B1r65vI4ke.png)

Đọc lại thì thấy có chữ C là in hoa nên mình chỉnh lại

![image](https://hackmd.io/_uploads/BJgUiPIV1l.png)

Flag : DH{Too_H4rd_to_sEe_th3_Ch4rs_x.x}

## ex-reg-ex

![image](https://hackmd.io/_uploads/B1UZpDU4yg.png)

<details>
<summary>app.py</summary>

```python
#!/usr/bin/python3
from flask import Flask, request, render_template
import re

app = Flask(__name__)

try:
    FLAG = open("./flag.txt", "r").read()       # flag is here!
except:
    FLAG = "[**FLAG**]"

@app.route("/", methods = ["GET", "POST"])
def index():
    input_val = ""
    if request.method == "POST":
        input_val = request.form.get("input_val", "")
        m = re.match(r'dr\w{5,7}e\d+am@[a-z]{3,7}\.\w+', input_val)
        if m:
            return render_template("index.html", pre_txt=input_val, flag=FLAG)
    return render_template("index.html", pre_txt=input_val, flag='?')

app.run(host="0.0.0.0", port=8000)
```

</details>

Đề yêu cầu gen ra một string match với regex trong code nên mình gen theo đó

![image](https://hackmd.io/_uploads/SJ_fTPINkg.png)

Payload : **draaaaae00am@aaa.a**

Nộp và có flag

![image](https://hackmd.io/_uploads/rkoQ6P8NJx.png)

Flag : DH{e64a267ab73ae3cea7ff1255b5f08f3e5761defbfa6b99f71cbda74b7a717db3}

## image-storage

![image](https://hackmd.io/_uploads/SyJTku8E1x.png)

Bài này là cổ điển của bug file upload vulnerable
Mình thực hiện upload 1 ảnh lên 

![image](https://hackmd.io/_uploads/r1JkxdL4yl.png)

![image](https://hackmd.io/_uploads/SJOxlu8Nkl.png)

Và nếu mình chỉnh lại là upload một file php thì sao? Bùm, mình có thể sử dụng linux command trên đây

![image](https://hackmd.io/_uploads/rkvElOLNkl.png)

![image](https://hackmd.io/_uploads/SJANeuLNJx.png)

Thay đổi đối tượng cần đọc và mình có flag

![image](https://hackmd.io/_uploads/SyehxuLVyx.png)

![image](https://hackmd.io/_uploads/HJLnxd8Nyx.png)

Flag : DH{c29f44ea17b29d8b76001f32e8997bab}

## command-injection-1

![image](https://hackmd.io/_uploads/Syvxkf8Nyl.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/env python3
import subprocess

from flask import Flask, request, render_template, redirect

from flag import FLAG

APP = Flask(__name__)


@APP.route('/')
def index():
    return render_template('index.html')


@APP.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 "127.0.0.1";cat flag.py#"'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')


if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8000)
```    

</details>

Bài này khá giống bài command-injection-chatgpt nhưng khác là có pattern của input

![image](https://hackmd.io/_uploads/HJSZ1ML4kl.png)

![image](https://hackmd.io/_uploads/HyhEyG84yg.png)

Sau khi mình thử payload sau và không thành công
127.0.0.1";cat flag.py"

![image](https://hackmd.io/_uploads/HyyqkMU4yg.png)

Mình tiến hành xoá pattern và có thể submit được input

![image](https://hackmd.io/_uploads/HJj51zUNkx.png)

Sau đó chúng ta có flag

![image](https://hackmd.io/_uploads/rkkhkf841l.png)

## File Vulnerability Advanced for linux

![image](https://hackmd.io/_uploads/HJLQPdLNJg.png)

<details>
<summary>main.py</summary>

```python
import os, subprocess
from functools import wraps
from flask import Flask, request

app = Flask(__name__)
API_KEY = os.environ.get('API_KEY', None)

def key_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        apikey = request.args.get('API_KEY', None)
        if API_KEY and apikey:
            if apikey == API_KEY:
                return view(**kwargs)
        return 'Access Denied !'
    return wrapped_view


@app.route('/', methods=['GET'])
def index():
    return 'API Index'


@app.route('/file', methods=['GET'])
def file():
    path = request.args.get('path', None)
    if path:
        data = open('./files/' + path).read()
        return data
    return 'Error !'


@app.route('/admin', methods=['GET'])
@key_required
def admin():
    cmd = request.args.get('cmd', None)
    if cmd:
        result = subprocess.getoutput(cmd)
        return result
    else:
        return 'Error !'


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

</details>

Mình thử đọc file /etc/passwd và xác nhận web bị lỗi path-traversal

![image](https://hackmd.io/_uploads/Sy0DwdLE1x.png)

sau dó mình đọc file log của nginx để lấy API_KEY

![image](https://hackmd.io/_uploads/BJRdwdLN1e.png)

![image](https://hackmd.io/_uploads/Bk99w_8VJx.png)

submit với API_KEY để bypass hàm key_required và chúng ta đã có flag

![image](https://hackmd.io/_uploads/BynswOUE1e.png)

![image](https://hackmd.io/_uploads/H1OnDOLVkx.png)

Flag : DH{2a4ff4e94d09793c662d1bd7ec5d497d7b190c6f}

## what-is-my-ip

![image](https://hackmd.io/_uploads/B18-WhUVJx.png)

<details>
<summary>app.py</summary>

```python
#!/usr/bin/python3
import os
from subprocess import run, TimeoutExpired
from flask import Flask, request, render_template

app = Flask(__name__)
app.secret_key = os.urandom(64)


@app.route('/')
def flag():
    user_ip = request.access_route[0] if request.access_route else request.remote_addr
    try:
        result = run(
            ["/bin/bash", "-c", f"echo {user_ip}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return render_template("ip.html", result=result.stdout)

    except TimeoutExpired:
        return render_template("ip.html", result="Timeout!")


app.run(host='0.0.0.0', port=3000)
```

</details>

Trong dockerfile mình thấy file flag được chuyển vào thư mục root

![image](https://hackmd.io/_uploads/rksGZ2UNJl.png)

Xem thử điều kiện đẻ chạy lệnh ping thì yêu cầu request phải được set access_route

![image](https://hackmd.io/_uploads/Byumb3L4Jl.png)

Xem hàm access_route thì yêu cầu phải có header X-Forwarded-For trong request

![image](https://hackmd.io/_uploads/H1RVbnU41g.png)

Mình thử request như bình thường để xem ping

![image](https://hackmd.io/_uploads/B1gIZnI4Jx.png)

Nên mình thêm vào header X-Forwarded-For và sử dụng payload sau để lấy được flag

![image](https://hackmd.io/_uploads/S1UO-hUE1g.png)

Flag : DH{1acfe9db38697eb71538e97e71882f1ad6deb5cb9d8c3448bd05d3adb805e559}

## EZ_command_injection

![image](https://hackmd.io/_uploads/HyUfJUwVJe.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/env python3
import subprocess
import ipaddress
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '')
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        error_msg = 'Invalid IP address'
        print(error_msg)
        return render_template('index.html', result=error_msg)

    cmd = f'ping -c 3 {addr}'
    try:
        output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=8)
        return render_template('index.html', result=output.decode('utf-8'))
    except subprocess.TimeoutExpired:
        error_msg = 'Timeout!!!!'
        print(error_msg)
        return render_template('index.html', result=error_msg)
    except subprocess.CalledProcessError:
        error_msg = 'An error occurred while executing the command'
        print(error_msg)
        return render_template('index.html', result=error_msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)    
```
    
</details>

Có thể thấy trang web nhận vào param host trong endpoint /ping để lấy kết quả ping
Ở phân format string trong cmd ta thấy có truyền vào addr là host là param mà ta đưa vào
Nhưng... addr này sẽ bị check bởi hàm **ipaddress.ip_address** dùng để check IP có hợp lệ hay không
Vậy làm sao để bypass hàm này ?

![image](https://hackmd.io/_uploads/BJxkZUvE1g.png)

Mình thử xài các bypass cũ nhưng hàm này không check được 
Nên mình thử đọc doc của hàm này 

Ở đây hàm ipaddress sẽ kiểm tra có phải là IPv4 hoặc IPv6 không

![image](https://hackmd.io/_uploads/H1WfZUDNkg.png)

Ở hàm check IPv4 ta có điều kiện như sau

![image](https://hackmd.io/_uploads/r17XZLPN1g.png)

Ở hàm check IPv6 tương tự ta cũng có

![image](https://hackmd.io/_uploads/H1-VWIDNkg.png)

Vậy vấn đề là hàm check IPv4 sẽ nhận vào một IP và pass nó vào filter %s/%d để ngăn cách với prefixlen vì thế các payload trên khi truyền vào sẽ có ip không phù hợp hoặc nếu có / thì phần prefixlen cũng không phải số nguyên để check
Ví dụ như : 172.22.32.82/20

Còn hàm IPv6 sẽ check chuỗi ip % scope_id
Nói thêm và scope_id thì được dùng để xác định network nào được link với mạng cục bộ
https://networkengineering.stackexchange.com/questions/46653/what-is-the-use-of-the-ipv6-scope-id
Vì thế trường scope_id có thể chưa chữ cái
Chúng ta xây dựng payload như sau : 

```0000:0000:0000:0000:0000:0000:0000:0000%;cat<flag.txt ```
Trong đó phần đầu là ip và phần sau ";cat<flag.txt" là scope_id khi filter vào cmd thì ta có lệnh sau 

```ping -c 3 0000:0000:0000:0000:0000:0000:0000:0000%;cat<flag.txt ```

Từ đó lệnh sẽ có 2 lệnh để thực thi và lệnh sau để lấy flag

![image](https://hackmd.io/_uploads/rykHDUPVye.png)

Flag : DH{EZZZZZ_COMm4Nd_1nJecTiON_ZzZZ}


## XSS Filtering Bypass

![image](https://hackmd.io/_uploads/r1z8g4-rke.png)

Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SkxdlE-Hyg.png)

Trang web mô phỏng lỗi XSS cơ bản nên mình có thể sử dụng payload như sau

`<img src=x oonnerror=fetch('/memo?memo=123') />`

![image](https://hackmd.io/_uploads/rJEDeNWH1g.png)

Vì web có replace các chữ như "on" để secure nhưng mình có thể sử dụng payload sau để bypass

`<img src=x oonnerror=fetch('/memo?memo='+document.cookie) />`

Report để bot vào xem và ta có flag

![image](https://hackmd.io/_uploads/rJZce4bryg.png)

Flag : DH{81cd7cb24a49ad75b9ba37c2b0cda4ea}

## simple-ssti

![image](https://hackmd.io/_uploads/rJy8rV-Bkg.png)

Đề bài cho mình một trang web mô phỏng lỗ hổng SSTI và source như sau

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template, render_template_string, make_response, redirect, url_for
import socket

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

app.secret_key = FLAG


@app.route('/')
def index():
    return render_template('index.html')

@app.errorhandler(404)
def Error404(e):
    template = '''
    <div class="center">
        <h1>Page Not Found.</h1>
        <h3>%s</h3>
    </div>
''' % (request.path)
    return render_template_string(template), 404

app.run(host='0.0.0.0', port=8000)    
```    

</details>

Có thể thấy các endpoint mình truyền vào sẽ được đưa vào web 

![image](https://hackmd.io/_uploads/S1wUHN-Syg.png)

![image](https://hackmd.io/_uploads/SkbPSVbByg.png)

Mình thử một payload {{7*7}} như sau và đã SSTI được

![image](https://hackmd.io/_uploads/ByHuSVZryl.png)

Cuối cùng mình thử đọc config và có flag

![image](https://hackmd.io/_uploads/BJtCSN-Syx.png)

Ngoài ra chúng ta cũng có thể xài các payload khác như sau

`/%7B%7Bconfig.SECRET_KEY%7D%7D`

`/%7B%7Bself._TemplateReference__context.joiner.__init__.__globals__.os.popen('cat%20./flag.txt').read()%7D%7D`

`/%7B%7Brequest.application.__globals__.__builtins__.__import__('os').popen('cat%20./flag.txt').read()%7D%7D`

`/%7B%7Brequest%7Cattr('application')%7Cattr('/x5f/x5fglobals/x5f/x5f')%7Cattr('/x5f/x5fgetitem/x5f/x5f')('/x5f/x5fbuiltins/x5f/x5f')%7Cattr('/x5f/x5fgetitem/x5f/x5f')('/x5f/x5fimport/x5f/x5f')('os')%7Cattr('popen')('cat%20./flag.txt')%7Cattr('read')()%7D%7D`

## simple-phparse

![image](https://hackmd.io/_uploads/BySCdL-rkg.png)

Bài này là một bài check path cơ bản mình có thể bypass bằng cách đổi ký tự như sau

%66lag.php

![image](https://hackmd.io/_uploads/ryXlKUWr1l.png)

## CSRF Advanced

![image](https://hackmd.io/_uploads/rkbAdB4BJe.png)

Bài này là một bài csrf lợi dụng để đổi mật khẩu admin thôi

![image](https://hackmd.io/_uploads/S1-xKBVrke.png)

Mình đọc source thì đã có thể tìm được csrf token của admin 

![image](https://hackmd.io/_uploads/HJYzYBNSJe.png)

Sau đó report payload này để đổi mật khẩu

`<img src='/change_password?pw=123&csrftoken=7505b9c72ab4aa94b1a4ed7b207b67fb' />`

Có mật khẩu là 123 thì đăng nhập vào và ta có flag

![image](https://hackmd.io/_uploads/HkBVYB4r1l.png)

Flag: DH{77bb582329a1b2fc9f8dc2a50b70d586}

## simple-sqli-chatgpt

![image](https://hackmd.io/_uploads/BJl3ziUBJe.png)

Bài này mô phỏng lỗi SQL injection

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/python3
from flask import Flask, request, render_template, g
import sqlite3
import os
import binascii

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

DATABASE = "database.db"
if os.path.exists(DATABASE) == False:
    db = sqlite3.connect(DATABASE)
    db.execute('create table users(userid char(100), userpassword char(100), userlevel integer);')
    db.execute(f'insert into users(userid, userpassword, userlevel) values ("guest", "guest", 0), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}", 0);')
    db.commit()
    db.close()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def query_db(query, one=True):
    cur = get_db().execute(query)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userlevel = request.form.get('userlevel')
        res = query_db(f"select * from users where userlevel='{userlevel}'")
        if res:
            userid = res[0]
            userlevel = res[2]
            print(userid, userlevel)
            if userid == 'admin' and userlevel == 0:
                return f'hello {userid} flag is {FLAG}'
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'

app.run(host='0.0.0.0', port=8000)
```
    
</details>

Đọc qua thì mình thấy rõ lỗi luôn. Chỗ select mình có thể thêm vào userid là admin để đăng nhập vào

`0' and userid = 'admin' --`

Và ta có flag

![image](https://hackmd.io/_uploads/Sy62QjLBye.png)

## Secure Secret

![image](https://hackmd.io/_uploads/BJOCtAPrkg.png)

<details>
<summary>app.py</summary>
    
```python
#!/usr/bin/env python3
import os
import string
from flask import Flask, request, abort, render_template, session

SECRETS_PATH = 'secrets/'
ALLOWED_CHARACTERS = string.ascii_letters + string.digits + '/'

app = Flask(__name__)
app.secret_key = os.urandom(32)

# create sample file
with open(f'{SECRETS_PATH}/sample', 'w') as f:
    f.write('Hello, world :)')

# create flag file
flag_dir = SECRETS_PATH + os.urandom(32).hex()
os.mkdir(flag_dir)
flag_path = flag_dir + '/flag'
with open('/flag', 'r') as f0, open(flag_path, 'w') as f1:
    f1.write(f0.read())


@app.route('/', methods=['GET'])
def get_index():
    # safely save the secret into session data
    session['secret'] = flag_path

    # provide file read functionality
    path = request.args.get('path')
    if not isinstance(path, str) or path == '':
        return render_template('index.html', msg='input the path!')

    if any(ch not in ALLOWED_CHARACTERS for ch in path):
        return render_template('index.html', msg='invalid path!')

    full_path = f'./{SECRETS_PATH}{path}'
    if not os.path.isfile(full_path):
        return render_template('index.html', msg='invalid path!')

    try:
        with open(full_path, 'r') as f:
            return render_template('index.html', msg=f.read())
    except:
        abort(500)
```
    
</details>

Sau khi đọc source thì nó yêu cầu mình đọc một file nào đó với tên file được ẩn.

Nhưng ở đây nó lại bỏ tên file vào session 
    
![image](https://hackmd.io/_uploads/H1eMq0vB1x.png)

Mình tiến hành decode lại bằng tool sau https://github.com/mprunet/flask_util và biết được tên file

![image](https://hackmd.io/_uploads/Bys79ADH1x.png)

Bây giờ chỉ cần điền vào và ta có flag

![image](https://hackmd.io/_uploads/SJ-rq0PB1l.png)

Flag : DH{FL4SK_S3SH_D3CRYP7ABL3:kqdhARr2icckydckS6NNmA==}
    
