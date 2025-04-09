---
title: "KalmarCTF 2025"
description: "KalmarCTF 2025"
summary: "KalmarCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-03-10
draft: false
cover: ../../post/kalmar2025/feature.png

authors:
  - winky
---


## RWX - Bronze

![image](https://hackmd.io/_uploads/H1qJHQhsyl.png)

### Solution

Challenge cho mình một trang web với 3 chức năng là đọc, ghi file và thực hiện lệnh linux nhưng chỉ giới hạn 7 char.

```python
from flask import Flask, request, send_file
import subprocess

app = Flask(__name__)

@app.route('/read')
def read():
    filename = request.args.get('filename', '')
    try:
        return send_file(filename)
    except Exception as e:
        return str(e), 400

@app.route('/write', methods=['POST'])
def write():
    filename = request.args.get('filename', '')
    content = request.get_data()
    try:
        with open(filename, 'wb') as f:
            f.write(content)
        return 'OK'
    except Exception as e:
        return str(e), 400

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 7:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6664)
```

Ở đây flag được đưa vào thư mục root và cấp quyền chỉ admin mới đọc được. 

```dockerfile
WORKDIR /
COPY flag.txt /
RUN chmod 400 /flag.txt

COPY would.c /
RUN gcc -o would would.c && \
    chmod 6111 would && \
    rm would.c
```

Ngoài ra challenge còn cho ta một file read flag như sau yêu cầu phải có argument là một chuỗi "you be so kind to provide me with a flag"

```c!
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char full_cmd[256] = {0}; 
    for (int i = 1; i < argc; i++) {
        strncat(full_cmd, argv[i], sizeof(full_cmd) - strlen(full_cmd) - 1);
        if (i < argc - 1) strncat(full_cmd, " ", sizeof(full_cmd) - strlen(full_cmd) - 1);
    }

    if (strstr(full_cmd, "you be so kind to provide me with a flag")) {
        FILE *flag = fopen("/flag.txt", "r");
        if (flag) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), flag)) {
                printf("%s", buffer);
            }
            fclose(flag);
            return 0;
        }
    }

    printf("Invalid usage: %s\n", full_cmd);
    return 1;
}
```

Vì thế để đọc được flag ta phải thực hiện lệnh sau `/would you be so kind to provide me with a flag` nhưng lại không thỏa yêu cầu tối đa 7 char. Lúc này mình sẽ sử dụng endpoint /write tạo ra một shell script và chạy lệnh `sh ~/a` chỉ có 6 char nên sẽ bypass thành công. Đầu tiên ta xác định vị trí thư mục ~ là ở /home/user 

![image](https://hackmd.io/_uploads/S1ZfB92oyg.png)

Tiến hành ghi vào file shell lệnh read flag trên

![image](https://hackmd.io/_uploads/HJeLSc2s1g.png)

Kiểm tra nội dung file shell và thấy rằng lệnh shell đã ghi vào thành công

![image](https://hackmd.io/_uploads/ryYPBc2jke.png)

Bây giờ chỉ cần thực thi shell script bằng sh là xong 

![image](https://hackmd.io/_uploads/S1Lqr5nike.png)

`kalmar{ok_you_demonstrated_your_rwx_abilities_but_let_us_put_you_to_the_test_for_real_now}`

## RWX - Silver

![image](https://hackmd.io/_uploads/H1qJHQhsyl.png)

### Solution

Bài này giông với bài Bronze nhưng /exec chỉ giới hạn lệnh tối đa 5 char.

```python
from flask import Flask, request, send_file
import subprocess

app = Flask(__name__)

@app.route('/read')
def read():
    filename = request.args.get('filename', '')
    try:
        return send_file(filename)
    except Exception as e:
        return str(e), 400

@app.route('/write', methods=['POST'])
def write():
    filename = request.args.get('filename', '')
    content = request.get_data()
    try:
        with open(filename, 'wb') as f:
            f.write(content)
        return 'OK'
    except Exception as e:
        return str(e), 400

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 5:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6664)
```

Ở đây chúng ta cần biết rằng `.` là một shell builtin tương đương với lệnh source của linux

![image](https://hackmd.io/_uploads/rkFJUjho1e.png)

Từ đó mình sẽ thực hiện như bài Bronze nhưng ở bước cuối mình sẽ thực hiện lệnh sau `. ~/a` để bypass 

![image](https://hackmd.io/_uploads/BJYnI92i1e.png)

`kalmar{impressive_that_you_managed_to_get_this_far_but_surely_silver_is_where_your_rwx_adventure_ends_b4284b024113}`

## babyKalmarCTF

![image](https://hackmd.io/_uploads/rklMPq2oJl.png)

### Solution

Challenge cho mình một trang web CTF như sau

![image](https://hackmd.io/_uploads/H1lKw9hjJl.png)

Ở đây web sẽ có các challenge impossible với tổng điểm 4000 và các challenge dễ hơn.

![image](https://hackmd.io/_uploads/HkeAwqhjkl.png)

Để lấy được flag chúng ta phải lấy được top 1 của web này.

![image](https://hackmd.io/_uploads/HkNJuq2okg.png)

Lúc này mình đọc source của hàm get_score mà trang web này dùng thì thấy rằng hàm tính value đã bị đổi và nhận vào team_count là maxSolves tức càng nhiều team thì điểm challenge càng cao.

![image](https://hackmd.io/_uploads/S17CK53skx.png)

Ok thì mình đã xác định được hướng giải là tạo thật nhiều account để buff điểm các bài dễ lên, với số lượng là 5 bài và hơn 900 điểm mỗi bài thì ta chắc chắn sẽ có top 1. Có 1 vấn đề là khi register nó đã dính CSP để chống CSRF nên ta không thể spam request được.

![image](https://hackmd.io/_uploads/HJ1-h93sJl.png)

Lúc này mình chỉ cần sử dụng webdriver để tạo là được. Đây là script để tạo 100 user bằng selenium.

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import string
import random
import time

browser = webdriver.Firefox()
browser.get('https://957d8491456aacec91258c75e9e18bb8-60507.inst1.chal-kalmarc.tf/register')

def id_generator(size=10, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

for i in range(100):

    name = id_generator()
    email = name + '@' + name + '.' + name
    print(name, email)

    elem1 = browser.find_element(By.NAME, 'name')
    elem1.send_keys(name)

    elem2 = browser.find_element(By.NAME, 'email')
    elem2.send_keys(email)

    elem3 = browser.find_element(By.NAME, 'password')
    elem3.send_keys(email)

    elem4 = browser.find_element(By.NAME, '_submit')
    elem4.click()

    elem5 = browser.find_element(By.XPATH, '/html/body/main/div[2]/div[2]/div[2]/a')
    elem5.click()

    elem6 = browser.find_element(By.NAME, 'name')
    elem6.send_keys(name)

    elem7 = browser.find_element(By.NAME, 'password')
    elem7.send_keys(email)

    elem8 = browser.find_element(By.NAME, '_submit')
    elem8.click()

    elem11 = browser.find_element(By.XPATH, '/html/body/nav/div/div/ul[2]/li[5]/a/span[2]/i')
    elem11.click()

    elem12 = browser.find_element(By.XPATH, '/html/body/nav/div/div/ul[2]/li[1]/a')
    elem12.click()
```

Ok trong lúc đợi tạo user thì ta sẽ bắt đầu giải các challenge. Đầu tiên là một bài crypto về RSA.

![image](https://hackmd.io/_uploads/rJPuJs3oyl.png)

Challenge cho ta một file script và output như sau

```python
from Crypto.Util.number import getPrime

with open("flag.txt", "rb") as f:
    flag = f.read()

flag = int.from_bytes(flag, 'big')

e = 65537

p,q,r = [getPrime(512) for _ in "pqr"]

print(f'n1 = {p*q}')
print(f'c1 = {pow(flag, e, p*q)}')
print(f'n2 = {q*r}')
print(f'c2 = {pow(flag, e, q*r)}')
print(f'n3 = {r*p}')
print(f'c3 = {pow(flag, e, r*p)}')
```

```
n1 = 92045071469462918382808444819504749563961839349096597384482544087908047186245341810642171828493439415203636331750819922984117530107215197072782880474039650967711411408034481971170502798025943494586125686145145275611434604037182033168196599652119558449773401870500131970644786235514317736653798125756404891127
c1 = 83837022114533675382122799116377123399567305874353525217531313052347013266429457590484976944405567987615711918756165213164809141929523845319047846779529628627662566542055574929528850262048285117600900265045865263948170688845876052722196561247534915037323009007843324908963180407442831108561689170430284682827
n2 = 138872353325175299307460237192549876070806082965466021111327520189900415231224864814489473847190673904249096844311163666118481717154197936898625500598207447786178788728989474031735348581801399821380599701957041743964351118199095341359179067904834006929292304447601473687076874217599854120530320878903822568483
c2 = 108277854219556753624555311292632391078510528708411323024976641264748291782337772568140557355433905939549254699367886423180057883496836376992252188314404115061609464533109517754775889103063279929956348746519414221014574988017949824063805698193300538273109123053143777891136649709207700596337731172498156528258
n3 = 96873643524161216047523283610645732806192956944624208819078561364455621631633510067022852244593247313195537163455457833157440906743895116798782534912117642844197952559448815829606193149605373700004399064513744456542191695589096233791113561406431990041145854326610075794048654641871205275800952496149515217589
c3 = 87497536561550257160428999520415606634926951187670727897152089479182062251287235760026406551482417341218358001218344037520058606273067256839313353071151191482530927154606346622780052423032142990543077247694313298271089760031393294084220768215879358822723955182536249471261313038497315002109953940648304272403
```

Vì bài này khá dễ nên mình có thể xây dựng solve script như sau 

```python
from Crypto.Util.number import long_to_bytes, inverse, GCD

n1 = 92045071469462918382808444819504749563961839349096597384482544087908047186245341810642171828493439415203636331750819922984117530107215197072782880474039650967711411408034481971170502798025943494586125686145145275611434604037182033168196599652119558449773401870500131970644786235514317736653798125756404891127
c1 = 83837022114533675382122799116377123399567305874353525217531313052347013266429457590484976944405567987615711918756165213164809141929523845319047846779529628627662566542055574929528850262048285117600900265045865263948170688845876052722196561247534915037323009007843324908963180407442831108561689170430284682827

n2 = 138872353325175299307460237192549876070806082965466021111327520189900415231224864814489473847190673904249096844311163666118481717154197936898625500598207447786178788728989474031735348581801399821380599701957041743964351118199095341359179067904834006929292304447601473687076874217599854120530320878903822568483
c2 = 108277854219556753624555311292632391078510528708411323024976641264748291782337772568140557355433905939549254699367886423180057883496836376992252188314404115061609464533109517754775889103063279929956348746519414221014574988017949824063805698193300538273109123053143777891136649709207700596337731172498156528258

n3 = 96873643524161216047523283610645732806192956944624208819078561364455621631633510067022852244593247313195537163455457833157440906743895116798782534912117642844197952559448815829606193149605373700004399064513744456542191695589096233791113561406431990041145854326610075794048654641871205275800952496149515217589
c3 = 87497536561550257160428999520415606634926951187670727897152089479182062251287235760026406551482417341218358001218344037520058606273067256839313353071151191482530927154606346622780052423032142990543077247694313298271089760031393294084220768215879358822723955182536249471261313038497315002109953940648304272403

e = 65537
q = GCD(n1, n2)
r = GCD(n2, n3)
p = GCD(n3, n1)
phi_n1 = (p - 1) * (q - 1)
d = inverse(e, phi_n1)
m = pow(c1, d, n1)

flag = long_to_bytes(m).decode()
print(flag)
```

Và ta đã có flag đầu tiên

![image](https://hackmd.io/_uploads/S1yMJoniyl.png)

`babykalmar{wow_you_are_an_rsa_master!!!!!}`

![image](https://hackmd.io/_uploads/SkRYkjhoJl.png)

Ở bài rev này mình bật ghidra lên đọc và có luôn flag

![image](https://hackmd.io/_uploads/SJqayo2ikx.png)

`babykalmar{string_compare_rev_ayoooooooo}`

![image](https://hackmd.io/_uploads/Hk8Jgs2iyg.png)


Challenge cho mình một bức ảnh 

![osintchallenge (1)](https://hackmd.io/_uploads/SkkYejhoye.jpg)

Sử dụng google lens và mình có luôn city của chỗ này là Aarhus

![image](https://hackmd.io/_uploads/S1r0_j2i1l.png)

`babykalmar{aarhus}`

![image](https://hackmd.io/_uploads/H1x1bs2sJe.png)

Challenge cho ta các một đoạn chữ Braille

`⠃⠁⠃⠽⠅⠁⠇⠍⠁⠗{⠎⠥⠏⠑⠗⠕⠗⠊⠛⠊⠝⠁⠇⠍⠕⠗⠎⠑⠉⠕⠙⠑⠉⠓⠁⠇⠇⠑⠝⠛⠑}`

Sử dụng tool decode online và mình cos được flag

![image](https://hackmd.io/_uploads/rJnt-j2okx.png)

`babykalmar{superoriginalmorsecodechallenge}`

![image](https://hackmd.io/_uploads/SkKobjnoJg.png)

Challenge welcome này đã tự cho ta flag

`babykalmar{welcome_to_babykalmar_CTF}`

Tiếp theo ta submit cả 5 bài và đều có điểm trên 900

![image](https://hackmd.io/_uploads/Hy1Mfj3jkg.png)

Cộng lại và mình đã top 1 server

![image](https://hackmd.io/_uploads/BJy7MshoJg.png)

Bây giờ chỉ việc lấy flag thôi

![image](https://hackmd.io/_uploads/SkCmGo2jJx.png)

`Flag: kalmar{w0w_y0u_b34t_k4lm4r_1n_4_c7f?!?}`

## Ez ⛳ v3

![image](https://hackmd.io/_uploads/Hk5AYbpske.png)

### Hints

Host header attack, SSRF and SSTI

### Solution

Challenge cho ta một web server sử dụng Caddy

```nginx
{
        debug
        servers  {
                strict_sni_host insecure_off
        }
}

*.caddy.chal-kalmarc.tf {
        tls internal
        redir public.caddy.chal-kalmarc.tf
}

public.caddy.chal-kalmarc.tf {
        tls internal
        respond "PUBLIC LANDING PAGE. NO FUN HERE."
}

private.caddy.chal-kalmarc.tf {
        # Only admin with local mTLS cert can access
        tls internal {
                client_auth {
                        mode require_and_verify
                        trust_pool pki_root {
                                authority local
                        }
                }
        }

        # ... and you need to be on the server to get the flag
        route /flag {
                @denied1 not remote_ip 127.0.0.1
                respond @denied1 "No ..."

                # To be really really sure nobody gets the flag
                @denied2 `1 == 1`
                respond @denied2 "Would be too easy, right?"

                # Okay, you can have the flag:
                respond {$FLAG}
        }
        templates
        respond /cat     `{{ cat "HELLO" "WORLD" }}`
        respond /fetch/* `{{ httpInclude "/{http.request.orig_uri.path.1}" }}`
        respond /headers `{{ .Req.Header | mustToPrettyJson }}`
        respond /ip      `{{ .ClientIP }}`
        respond /whoami  `{http.auth.user.id}`
        respond "UNKNOWN ACTION"
}
```

Phân tích: 

* Mục tiêu của ta là vào private.caddy.chal-kalmarc.tf để lấy flag

* Nhưng khi vào các subdomain có dạng `*.caddy.chal-kalmarc.tf` thì đều redirect về  public.caddy.chal-kalmarc.tf nên ta không thể bypass được 

* Ở đây ta sẽ quan tâm `strict_sni_host insecure_off` là một option cho phép ta sử dụng Host header khong cần match với url tức là chúng ta có thể sử dụng url từ nguồn khác.

![image](https://hackmd.io/_uploads/H1aqZfTo1g.png)

Ở đầy mình thay đổi host thành public.caddy.chal-kalmarc.tf và có được respond như trong file chứ không còn redirect nữa

![image](https://hackmd.io/_uploads/Syx_kzfpoyg.png)

Ok đến đây thì mình chỉ cần vào endpoint /flag của private.caddy.chal-kalmarc.tf

![image](https://hackmd.io/_uploads/B1TWSf6j1x.png)

Nhưng không web đã giới hạn ip gửi request phải là từ localhost túc là từ chính máy đang chạy server

```
@denied1 not remote_ip 127.0.0.1
respond @denied1 "No ..."
```

Ta quan sát kỹ lại thì thấy có endpoint /fetch dùng để lấy thông tin từ endpoint khác và không bị giới hạn 

```
respond /fetch/* `{{ httpInclude "/{http.request.orig_uri.path.1}" }}`
```

Lúc này mình sẽ sử dụng /fetch/flag để lấy nội dung từ /flag và đã thành công

![image](https://hackmd.io/_uploads/r1z4rMajkg.png)

Nhưng nó lại không trả ra flag vì bị chặn bởi 

```
@denied2 `1 == 1`
respond @denied2 "Would be too easy, right?"
```

Ok lúc này thì hết cách bypass rồi chúng ta quan sát và thấy /headers đùng để trả ra các header mà request của mình gửi tới server

![image](https://hackmd.io/_uploads/SktIHfpiyx.png)

Lúc này mình mới research và biết rằng có template có thể lấy biến từ environment mà flag thì nằm trong đó. https://caddyserver.com/docs/modules/http.handlers.templates

![image](https://hackmd.io/_uploads/rJ8i55HnJx.png)

Craft payload vào header và ta đã thực hiện SSTI thành công.

![image](https://hackmd.io/_uploads/HyA9UMaoye.png)

`FLag: kalmar{4n0th3r_K4lmarCTF_An0Th3R_C4ddy_Ch4ll}`

## KalmarNotes

Updating ...