---
title: "USC CTF FALL 2024"
description: "USC CTF FALL 2024"
summary: "USC CTF FALL 2024 writeup"
categories: ["Writeup"]
tags: ["Web", "Forensics"]
#externalUrl: ""
date: 2024-11-08
draft: false
cover: ../../post/usc2024/feature.jpg
authors:
  - winky
---

| Category | Challenge Name | Difficulty |
| -------- | -------------- | ---------- |
| Forensics      | weirdtraffic  | Easy |
| Web      | iRobots | Easy |
| Web      | Tommy's Artventures | Easy |

## weirdtraffic

![image](https://hackmd.io/_uploads/BJpUqnVWyl.png)

#### Hints

* Đọc wireshark

#### Solution

Sau khi tải file pcapng về mình mở lên bằng wireshark và phát hiện một protocol chứa flag 

![image](https://hackmd.io/_uploads/ryb65h4Zkg.png)


![image](https://hackmd.io/_uploads/r1EAqnVZJl.png)
 
 
Flag : CYBORG{hping3-is-a-cool-tool}


## iRobots

![image](https://hackmd.io/_uploads/Sku1AiVWyx.png)

#### Hints
* Tôi yêu Burpsuite Pro

#### Solution

Giao diện website : 

![image](https://hackmd.io/_uploads/BJpgRoEbkl.png)

Mình thử mở devtool để xem và thấy đoạn script sau 

![image](https://hackmd.io/_uploads/B1850o4WJe.png)

Mình gõ thử mật khẩu là as1m0v và đến trang này

![image](https://hackmd.io/_uploads/SyF6RjE-Jl.png)

Sau một hồi suy nghĩ thì hình như nó đang đề cập đến một page ẩn nên mình xài Burpsuite để scan page

Sau khi crawl thì mình nhận được kết quả sau

![image](https://hackmd.io/_uploads/SyhGJnN-1e.png)

Thử truy cập vào file /hidden/flag.txt và mình đã có flag

![image](https://hackmd.io/_uploads/BJaSy2VWJl.png)

Flag : CYBORG{robots_txt_is_fun}

##  Tommy's Artventures

![image](https://hackmd.io/_uploads/rkp_JiEWkg.png)


#### Hints
* Bài này mình sẽ vào trang admin bằng flask session

#### Solution
Đề bài cho ta một file secret_key.txt với nội dung là 4a6282bf78c344a089a2dc5d2ca93ae6

Giao diện website chỉ có một nút login : 

![image](https://hackmd.io/_uploads/ryWklo4b1x.png)


Mình sẽ thử đăng ký và đăng nhập một tài khoản ngẫu nhiên

![image](https://hackmd.io/_uploads/HkBqgsEZJx.png)


Sau khi đăng nhập mình thấy có một button curate và phải là admin mới xem được 
![image](https://hackmd.io/_uploads/HkbPgoEbke.png)
![image](https://hackmd.io/_uploads/ryKDgs4bkg.png)


Mình thử bật devtool và thấy trang web chứa session

![image](https://hackmd.io/_uploads/HJ2y-sNWkg.png)

Mình thử tìm một vài tool để encode và decode session này và mình sẽ sử dụng tool [này](https://github.com/noraj/flask-session-cookie-manager)

Thực hiện git clone tool về và decode đoạn session trên mình biết được session giữ thông tin json dạng {"user" : username}
![image](https://hackmd.io/_uploads/HJxwZoVZkl.png)

Sau đó mình encode một đoạn session khác với "user" là "admin" và secret_key có trong file của đề

![image](https://hackmd.io/_uploads/SJKQGoE-1l.png)

Thay đổi session của web bằng đoạn session trên sau đó refresh trang, ta sẽ vào được user admin và thu được flag

![image](https://hackmd.io/_uploads/SyYFMsNWke.png)

![image](https://hackmd.io/_uploads/HknKMj4Zyg.png)

Flag : CYBORG{oce4n5_auth3N71ca7i0N}