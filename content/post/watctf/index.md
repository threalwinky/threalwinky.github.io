---
title: "WatCTF W25"
description: "WatCTF W25"
summary: "WatCTF W25 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-03-18
draft: false
cover: ../../post/watctf/feature.png

authors:
  - winky
---


Trong lúc hardcore picoCTF thì mình có ngó qua giải này để làm thử và đã clear web hehe 

![image](https://hackmd.io/_uploads/rJmiM5V2Jg.png)


## server-side-rendering

### Hints

Information disclosure

### Source

https://drive.google.com/file/d/1paYStYnOP2GbxsnKdT4fSzVCH8IGXUnv/view?usp=sharing

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/r10e3JSnJg.png)

Để lấy được flag ta phải có được password của admin mà khi hash ra trùng với ADMIN_PW_HASH

![image](https://hackmd.io/_uploads/Bkuq31HnJe.png)

```js
import styles from "../page.module.css";
import { cookies } from 'next/headers';
import sha256 from 'js-sha256';
import AdminPageImpl from './adminpageimpl';

const ADMIN_PW_HASH = "1b504583e27618fd2d5c5c07935f89e34b29cc60d34f045ed7a3567d68b89946";

export default async function AdminPanel() {

  const cookieStore = await cookies();
  let token = cookieStore.get('token');
  let isAdmin;
  if (typeof token === 'string' && sha256.hex(token) == ADMIN_PW_HASH) {
    isAdmin = true;
  } else {
    isAdmin = false;
  }

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <AdminPageImpl isAdmin={isAdmin} />
      </main>
    </div>
  );
}
```

Điều này khá là bất khả thi nhưng khi nhìn kỹ lại thì ta có thể xem được source của file page sau khi next js dump ra. Và vì biến flag chỉ là một string variable nên ta có thể dễ dàng tìm kiếm.

![image](https://hackmd.io/_uploads/Bk53nJrnkg.png)

`Flag: watctf{when_you_c0nfus3_th3_cl13nt_f0r_th3_s3rv3r_bad_things_happen}`

## works-modulo-security



### Source

https://drive.google.com/file/d/1WZecn6DRIfsmp4MREcgXRmZEdAEdRJ3V/view?usp=sharing

### Hints

Math

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/ryFy0kr2yl.png)

Và đây là backend của web 

```python
from flask import Flask, render_template, request, make_response, redirect
import random, os
from Crypto.Util.number import getPrime

app = Flask(__name__)

MOD = getPrime(128)

print("Mod: ",MOD)
def gen_id():
    return random.randint(1 << 127, 1 << 128)


def anonymize(user_id):
    return user_id + random.randint(1 << 127, 1 << 128) * MOD


def request_to_user(request):
    try:
        token = int(request.cookies["login_token"])
        return users[user_id_to_idx[token]]
    except:
        return False

admin = {"name": "admin", "id": gen_id(), "status": "administrative"}
admin['anon_id'] = anonymize(admin['id'])
print(admin["id"])
print(admin['anon_id'])
user_id_to_idx = {(admin["id"]): 0}
users = [admin]


def add_user(user):
    if len(users) < 1_000:
        idx = len(users)
        users.append(user)
    else:
        # We can't handle more than 1k users.
        # They probably won't notice, right?
        idx = random.randint(500, 600)
        del user_id_to_idx[users[idx]["id"]]
        users[idx] = user
    user_id_to_idx[user["id"]] = idx

allowed_statuses = ["😃 CHUMMY", "😃 BULLY", "😃 PALSY", "😃 PEPPY", "😃 CHIPPER", "😡 RANCOROUS"]

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

@app.route("/", methods=["GET", "POST"])
def index():
    user = request_to_user(request)
    err = ""
    if request.method == "POST":
        if 'status' in request.form:
            status = request.form['status']
            if status in allowed_statuses and user:
                user['status'] = status
            else:
                err = "invalid status!"
        else:
            err = "status not in form!"
    resp = make_response(
        render_template(
            "index.html", 
            users=reversed(users), 
            curr_user=user, 
            allowed_statuses=chunks(allowed_statuses,2),
            err=err
        )
    )
    return resp


@app.route("/flag")
def flag():
    # Only the admin can access the flag!
    user = request_to_user(request)
    if user and user["id"] == admin["id"]:
        return make_response(
            os.environ["FLAG"] if 'FLAG' in os.environ else "don't hardcode secrets in source code!", 
            200
        )
    else:
        return make_response("Hey! You're not allowed to be here! Scram!", 401)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = {
            "name": request.form["username"],
            "id": gen_id(),
            "status": "nothing",
        }
        user['anon_id'] = anonymize(user['id'])
        add_user(user)
        resp = make_response(redirect("/"))
        resp.set_cookie("login_token", str(user["id"]))
        return resp
    else:
        return render_template("login.html")

app.run()
```

Phân tích: 

* Mỗi user sẽ có một id và một anon_id trong đó, anon_id được hiển thị ở ngoài web 
* Nhiệm vụ của ta là sẽ lấy id của admin
* Ta có thể tạo một user mới và có được id và anon_id của user đó từ đó có thể phân tích hàm anonymize 

![image](https://hackmd.io/_uploads/By_b0yS3Je.png)

Đầu tiên ta đăng nhập và có chuỗi id như sau: `247276391411241497014723160966847247072`. Ở đây tab của user hiện tại của mình đang nằm trong khoảng (500, 600) của 1000 user được display. Để tiện thì ta có thể sử dụng status này để tìm kiếm anon_id của mình.

![image](https://hackmd.io/_uploads/SkBLylSh1l.png)

Và nó nằm ở đây 

![image](https://hackmd.io/_uploads/H1mrJxSn1e.png)

Ta đọc lại hàm 

```python
def anonymize(user_id):
    return user_id + random.randint(1 << 127, 1 << 128) * MOD
```

thì thấy rằng mình có thể tính phần random.randint(1 << 127, 1 << 128) * MOD như sau

![image](https://hackmd.io/_uploads/Byfo1xHnJx.png)

Ok thì mình sẽ tiến hành factorize thằng `42376268993993121738914697775531557474796033113743122996685875589965701801906` xem và thấy là nó được cấu bởi 1 số nguyên tố có độ dài 39 chính là MOD = getPrime(128)


![image](https://hackmd.io/_uploads/SkBDeerhkg.png)

Vậy MOD = `223328289386090456848323691158886945043`. Tiếp theo ta cần tìm anon_id của admin chính là tab cuối cùng của web 

![image](https://hackmd.io/_uploads/H149egr2kg.png)

Vậy admin_anon_id = `59217110681742667708852107265115533703415803249984958482823283016033787252841`

Từ admin_anon_id và MOD ta có thể xây dựng được một phương trình bậc nhất như sau : `59217110681742667708852107265115533703415803249984958482823283016033787252841 = x + y * 223328289386090456848323691158886945043`

Tiếp theo ta tiến hành brute-force, để ý rằng x là random.randint(1 << 127, 1 << 128) có độ dài 39 nên sẽ nằm trong khoảng `100000000000000000000000000000000000000` đến `999999999999999999999999999999999999999`

Từ đó ta có 2 mốc để tính y như sau: `59217110681742667708852107265115533703415803249984958482823283016033787252841 = 100000000000000000000000000000000000000 + y * 223328289386090456848323691158886945043`

và 

`59217110681742667708852107265115533703415803249984958482823283016033787252841 = 999999999999999999999999999999999999999 + y * 223328289386090456848323691158886945043`

![image](https://hackmd.io/_uploads/SyKhWeSn1l.png)

Sau khi tính ra được y1 và y2 thì ta sẽ xét các số nằm trong khoảng này là những số có độ dài 39 sao cho ra được x cũng độ dài 39 thỏa mãn hàm anonymize 

=> y1 = 265157230391748496717608896859026795808
=> y2 = 265157230391748496717608896859026795804

Tiếp theo ta sẽ tìm kiếm các x dựa theo y

```python
for i in range(265157230391748496717608896859026795804, 265157230391748496717608896859026795808+1):
    target = 59217110681742667708852107265115533703415803249984958482823283016033787252841
    MOD = 223328289386090456848323691158886945043
    print("id: ", target - i * MOD)
```



![image](https://hackmd.io/_uploads/H1XOGgSh1g.png)

Thử các id trên và ta đã có flag ở id `312970591718841261469349864023708473097`

![image](https://hackmd.io/_uploads/rJ1sMeSnJl.png)

`Flag: watctf{m0dulus_f4ns_wh3n_you_show_th3m_gcd}`

## goose-intern-portal

### Source

https://drive.google.com/file/d/1rHex7-3R-urgX42nfW5-ZbmGvBhMnhT0/view?usp=sharing

### Hints

JWT algorithm confusion attack

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/rJC8XgB2ke.png)


```python
from flask import Flask, request, render_template_string, redirect, url_for, make_response
import jwt, os
from Crypto.PublicKey import RSA

app = Flask(__name__)

# RSA key pair
RSA_KEY = RSA.generate(2048)
PUBLIC_KEY = RSA_KEY.public_key().export_key().decode('utf-8')

FLAG = os.environ["FLAG"] if "FLAG" in os.environ else "don't hardcode secrets in source code!"

@app.route('/debug')
# def debug():
#     # Debugging JWT signing (COMMENT OUT IN PRODUCTION)
#     return RSA_KEY.export_key().decode('utf-8')

def get_hmac_secret():
    """Strip the header/footer and newlines from RSA_PUBLIC_KEY to form the HMAC secret."""
    lines = PUBLIC_KEY.strip().splitlines()
    return "".join(line for line in lines if "-----" not in line)

@app.route("/")
def index():
    # Dashboard page with a list of tasks (no token form).
    return render_template_string(index_template)

@app.route("/admin")
def admin():
    # ------------------------------------------------------------------
    # /admin endpoint: JWT is validated here.
    # Returns:
    #   - "Invalid Token" if token is missing or invalid.
    #   - "Access Denied" if token is valid but role is not 'admin'.
    #   - Success with the flag if the token is valid and role is 'admin'.
    # ------------------------------------------------------------------
    token = request.cookies.get("token")
    if not token:
        return render_template_string(error_template, error="Invalid Token")
    
    try:
        # Retrieve the token header without verification.
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") == "HS384":
            # Use the stripped public key as the HMAC secret.
            secret = get_hmac_secret()
            payload = jwt.decode(token, secret, algorithms=["HS384"])
        else:
            # For tokens not using HS384, verify normally using RS256.
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    except Exception as e:
        return render_template_string(error_template, error="Invalid Token")
    
    if payload.get("role") != "admin":
        return render_template_string(error_template, error="Access Denied")
    else:
        return render_template_string(admin_template, flag=FLAG)

# HTML templates

index_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Goose Inc. Intern Portal - Dashboard</title>
    <style>
        body {
            background: #f7f7f7;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .container {
            width: 700px;
            margin: 50px auto;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        h2, h3 {
            color: #0073e6;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        ul li {
            background: #e3f2fd;
            margin: 8px 0;
            padding: 10px;
            border-radius: 4px;
        }
        .info {
            margin-top: 20px;
            font-size: 0.9em;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome to Goose Inc. Intern Portal</h2>
        <h3>Dashboard</h3>
        <p>Your tasks for today:</p>
        <ul> <li>Complete your JWT configuration paperwork</li> <li>Review JWT authentication and authorization policies</li> <li>Set up your development environment for JWT implementation</li> <li>Attend the security briefing on token handling and storage</li> </ul>

        
        <!-- <p>To access the Admin Panel, send your JWT token in a cookie named <code>token</code> to the <code>/admin</code> endpoint.</p> -->
    </div>
</body>
</html>
"""

admin_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Goose Inc. Admin Panel</title>
    <style>
        body {
            background: #e0f7fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .container {
            width: 600px;
            margin: 50px auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }
        h2 {
            color: #00796b;
        }
        .flag {
            background: #b2dfdb;
            padding: 20px;
            border-radius: 4px;
            font-weight: bold;
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- /admin endpoint: JWT is validated here. On success, the secret flag is revealed below. -->
        <h2>Admin Panel</h2>
        <p>Welcome, Admin Intern. Here is your secret:</p>
        <div class="flag">{{ flag }}</div>
    </div>
</body>
</html>
"""

error_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <style>
        body {
            background: #ffebee;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .container {
            width: 400px;
            margin: 100px auto;
            background: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        h2 {
            color: #d32f2f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>{{ error }}</h2>
        <p>Please check your token and try again.</p>
    </div>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)

```

Ok thì dạng này mình đã làm khá nhiều rồi. Vì web sử dụng 2 thuật toán để kiểm tra signature là HS384 và RS256 và sử dụng chung public-key. Đầu tiên ta cần tìm public-key ở /debug 

![image](https://hackmd.io/_uploads/Hkk_7lSh1g.png)

Tạo một JWT token mới với secret là publickey vừa mới tìm được lưu ý là sử dụng thuật toán mã hóa HS384

![image](https://hackmd.io/_uploads/H13XEerh1g.png)

Có được JWT token thay vào và ta có flag

```
eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.rEolT-ac2sRUjEuQTfleXyc3R7at1Om5yuks4Cf18jejCMcWwVVXdDXw6Tf0ZxFA
```

![image](https://hackmd.io/_uploads/HJvUNeH21e.png)

`Flag: watctf{these_jwt_keys_g07_m3_c0nfu53d_12345}`
