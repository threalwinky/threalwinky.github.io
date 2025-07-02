---
title: "ACECTF 1.0"
description: "ACECTF 1.0"
summary: "ACECTF 1.0 writeup"
categories: ["Writeup"]
tags: ["Web", "Reverse", "Osint"]
#externalUrl: ""
date: 2025-02-28
draft: false
cover: ../../post/acectf2025/feature.png
authors:
  - winky
---




![Screenshot_2025-02-28_22-48-28](https://hackmd.io/_uploads/r1Y1iI1i1e.png)

Giải ACECTF vừa rồi mình có tham gia với team laevatain và giải được full web hehe

![image](https://hackmd.io/_uploads/ByFuyHks1e.png)

Sau đây là writeup những bài mà mình làm được và những bài mình có đóng góp

## reverse/Significance of Reversing

![image](https://hackmd.io/_uploads/SkeT_SkiJg.png)

### Source

https://drive.google.com/file/d/1IxQMP6PoWImRofFoHaX8ZhMYQUDxQloF/view?usp=sharing

### Hints

Reverse, ROT47 Cipher

### Solution

Challenge cho mình một ảnh png như sau. Mình thấy có một cái khá sú như là `s%s%s% :gnirts detpyrceD` thì đảo ngược lại sẽ thành `Decrypted string: %s%s%s` 

![image](https://hackmd.io/_uploads/SJJrFBJsyg.png)

Ok thì mình thử strings file này và reverse thì phát hiện đây là một binary file dùng để rot47 decrypt một string nào đó

<details>
<summary>strings-reverse</summary>
    
```vb-net
.comment
.bss
.data
.got.plt
.dynamic
.fini_array
.init_array
.eh_frame
.eh_frame_hdr
.rodata
.fini
.text
.plt.got
.init
.rela.plt
.rela.dyn
.gnu.version_r
.gnu.version
.dynstr
.dynsym
.gnu.hash
.note.ABI-tag
.note.gnu.build-id
.note.gnu.property
.interp
.shstrtab
.strtab
.symtab
_init
__cxa_finalize@GLIBC_2.2.5
_ITM_registerTMCloneTable
__TMC_END__
main
__bss_start
_end
_IO_stdin_used
__dso_handle
__gmon_start__
rot47_decrypt
__data_start
printf@GLIBC_2.2.5
_fini
_edata
_ITM_deregisterTMCloneTable
__libc_start_main@GLIBC_2.34
_GLOBAL_OFFSET_TABLE_
__GNU_EH_FRAME_HDR
_DYNAMIC
__FRAME_END__
revme.c
__frame_dummy_init_array_entry
frame_dummy
__do_global_dtors_aux_fini_array_entry
completed.0
__do_global_dtors_aux
deregister_tm_clones
crtstuff.c
__abi_tag
Scrt1.o
GCC: (Debian 14.2.0-8) 14.2.0
;*3$"
Decrypted string: %s%s%s
0CbGbCdbH
=<0c3_FfH
LHb0
prtr
< ~FH
u+UH
PTE1
_ITM_registerTMCloneTable
__gmon_start__
_ITM_deregisterTMCloneTable
GLIBC_2.34
GLIBC_2.2.5
libc.so.6
printf
__cxa_finalize
__libc_start_main
/lib64/ld-linux-x86-64.so.2
```

</details>

Đây là phần mà file decrypt

```
0CbGbCdbH
=<0c3_FfH
LHb0
prtr
< ~FH
u+UH
PTE1
```

Mình thử encrypt lại và nhận được kết quả sau. Có thể thấy kết quả dưới không đủ ghép được thành flag.

![image](https://hackmd.io/_uploads/SyK0qBJjJg.png)

Một anh teammate có bảo mình là strings nó sẽ lược mất vài ký tự nên mình sẽ reverse file png này và dump ra thành executable file

```python
with open("Reverseme.png", "rb") as f:
    byte = f.read(1)
    byte_array = b""
    while byte:
        char = byte
        byte_array += char
        byte = f.read(1)
    with open("execute", "wb") as f:
        f.write(byte_array[::-1])
```

Sau khi dump và chạy thì mình có flag

![image](https://hackmd.io/_uploads/r12hS8kikx.png)

`Flag: ACECTF{w3_74lk_4b0u7_r3v3r53}`

## osint/Fall of 2022


![image](https://hackmd.io/_uploads/SJmJIIkoke.png)

### Hints

TXT Record

### Solution

Mình thử tìm các TXT record của domain này và có luôn flag :vv

![image](https://hackmd.io/_uploads/rJPQ8IJoyg.png)

`Flag: ACECTF{y0u_g07_7h3_73x7`

## osint/The Mysterious Building

![image](https://hackmd.io/_uploads/rydSILysJl.png)

### Solution

Challenge cho mình một bức ảnh sau. Nhìn lúc đầu thì mình đoán được ở đây là Ấn Độ luôn. 

![OSINT-1](https://hackmd.io/_uploads/HkxLI8Jo1g.jpg)

Mình thử tìm tòa tháp kia thì có ngay kết quả là tháp Pitampura ở Ấn Độ.

![image](https://hackmd.io/_uploads/HJefcDLko1g.png)

Mình thử tìm trên Google Maps và đúng thật nó nằm gần một đường tàu điện đúng với đề đang miêu tả.

![Screenshot_2025-02-28_22-38-30](https://hackmd.io/_uploads/BkcodLJsJe.jpg)

Lúc này mình tìm các công trình xung quanh nhưng mà không thấy tòa nhà kế bên ở đâu cho đến khi mình tìm Google cụm từ `company near Pitampura TV Tower, Delhi, India` (Vì mình thấy tòa nhà có logo nên có khả năng là công ty nào đó)

![image](https://hackmd.io/_uploads/BJ8QuIJjyg.png)

Tìm hoài cũng không thấy, tự nhiên teammate L1ttl3 của team mình tinh mắt thấy có logo giống đang tìm. Và đó là tòa nhà mình cần tìm : `PP Trade Center`

![Screenshot_2025-02-28_22-41-29](https://hackmd.io/_uploads/BkHSt8kjyl.jpg)

Wow, thật ra nó nằm khá xa tòa tháp :)) 

![Screenshot_2025-02-28_22-43-06](https://hackmd.io/_uploads/SJXsFUkiye.jpg)

`Flag: ACECTF{pp_trade_center}`

## web/Buried Deep

![image](https://hackmd.io/_uploads/H1M11BJsye.png)

### Hints 

Scavenger Hunt

### Solution

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/ryyQgSJske.png)

Không thấy có gì sú cả nên mình thực hiện dirsearch trang web này và phát hiện 2 endpoint đáng nghi

![image](https://hackmd.io/_uploads/rkm7mr1oJg.png)

Vào robots.txt và mình thấy được các endpoint khác như sau

![image](https://hackmd.io/_uploads/SJAN7Sko1l.png)

Vào thử 5 cái đầu thì không có manh mối gì cả.

![image](https://hackmd.io/_uploads/BylImHJjJe.png)

![image](https://hackmd.io/_uploads/rkzD7B1i1x.png)

![image](https://hackmd.io/_uploads/HJdPQByiJx.png)

![image](https://hackmd.io/_uploads/S1EO7Syikx.png)

![image](https://hackmd.io/_uploads/Hygt7ByoJg.png)

Đến endpoint thứ 6 /buried thì mình thấy các số như sau

![image](https://hackmd.io/_uploads/rJ3K7H1oJl.png)

Trông như là thứ tự ASCII nên mình thử convert xem có gì hot

```python
s = "49 115 116 32 80 97 114 116 32 111 102 32 116 104 101 32 70 108 97 103 32 105 115 32 58 32 65 67 69 67 84 70 123 49 110 102 49 108 55 114 52 55 49 110 103 95 55 104 51 95 53 121 53 55 51 109 95 32"

for c in s.split():
    print(chr(int(c)), end="")
```

Sau khi convert thì mình có part đầu tiên của flag

![image](https://hackmd.io/_uploads/HkDeIrksJl.png)

`First part: ACECTF{1nf1l7r471ng_7h3_5y573m_`

Ok mình xem các endpoint tiếp theo 

![image](https://hackmd.io/_uploads/HJrDES1okx.png)

Đến /secret_path thì mình thấy các ký tự trông như mã Morse vậy

![image](https://hackmd.io/_uploads/BkeuVSkskx.png)

Mình tiến hành giãi mã và có luôn part thứ 2 

![image](https://hackmd.io/_uploads/Bk4jNr1iJe.png)

`Second part: 15_345y_wh3n_y0u_kn0w_wh3r3_`

Ok tiếp tục thôi

![image](https://hackmd.io/_uploads/HJM1rB1j1x.png)

![image](https://hackmd.io/_uploads/rJ91BH1sJg.png)

Đến /encrypted thì mình thấy nó đề cập đến gì đó về style nên mình lục thử xem có file css nào khả nghi không.

![image](https://hackmd.io/_uploads/S14grHki1l.png)

Và mình tìm được nó trong file css ở endpoint /

![image](https://hackmd.io/_uploads/S1YFBryjyx.png)

Ở đây khá may mắn vì mình làm bài rev trước có liên quan đến rot47 nên mình thử decrypt lại và có luôn được flag

```python
def rot47_decrypt(text):
    return ''.join(
        chr(((ord(c) - 33 - 47) % 94 + 33) if 33 <= ord(c) <= 126 else ord(c))
        for c in text
    )

print(rot47_decrypt(s))
```

![image](https://hackmd.io/_uploads/BJcBUrJskl.png)

```Third part: 7h3_53cr3t5_4r3_bur13d}```

Và mình có flag đầy đủ như sau

`Flag:ACECTF{1nf1l7r471ng_7h3_5y573m_15_345y_wh3n_y0u_kn0w_wh3r3_7h3_53cr3t5_4r3_bur13d}`

## web/Webrypto

![image](https://hackmd.io/_uploads/Bk5NF5A5Je.png)

### Hints

Type juggling

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SJc1t9C5Jg.png)

Ok thì tóm tắt nó sẽ lấy hai tham số khác nhau nhưng khi md5 với prefix 'ACECTF' thì nó phải giống nhau.

![image](https://hackmd.io/_uploads/SJtWF9Ccyx.png)

Lúc đầu mình tưởng là md5 hash collision hay gì đó nhưng mình chợt nhận ra mình có thể làm cho 2 thằng md5 trả ra null bằng cách truyền kiểu dữ liệu không phù hợp. Đến đây mình truyền 2 mảng vào và có flag.

![image](https://hackmd.io/_uploads/r1e7t5R51x.png)

`Flag: ACECTF{70m_4nd_j3rry_4r3_4ll135}`

## web/Token of Trust

![image](https://hackmd.io/_uploads/HJeLK5CcJg.png)

### Hints

JWT Crack

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SJAg55C9ye.png)

Ok thì làm theo hướng dẫn và mình nhận được một cái JWT Token như sau

![image](https://hackmd.io/_uploads/ByNwwSyi1e.png)

Mình thử xem payload của token này và phát hiện ra user trong token không phải user mà mình truyền vào

![image](https://hackmd.io/_uploads/ryuKwr1okx.png)

Đến đây mình thử dirsearch tiếp xem có gì hot

![image](https://hackmd.io/_uploads/HkrytBkike.png)

Trong /robots.txt ta thấy có một endpoint khác là /flag

![image](https://hackmd.io/_uploads/Hk5jwr1oJx.png)

Mình thử vào /flag và nhận được là Cannot GET /flag

![image](https://hackmd.io/_uploads/SJITvryskg.png)

Vậy là GET method không ăn nên mình thử POST xem. Có thể thấy web yêu cầu một token gì đó.

![image](https://hackmd.io/_uploads/Sk6JOBkskl.png)

Mình thử truyền token lúc nãy vào và nó lại yêu cầu là admin

![image](https://hackmd.io/_uploads/SymvdS1sJe.png)

Ở đây mình đổi user trong payload lại thành admin và secret mình để random luôn

![image](https://hackmd.io/_uploads/S1T__BJokl.png)

Và ta có flag. Ta có thể kết luận web không kiểm tra secret của token.

![image](https://hackmd.io/_uploads/ryAt_Hkoyl.png)

`Flag: ACECTF{jwt_cr4ck3d_4dm1n_4cce55_0bt41n3d!}`

## web/Flag-Fetcher

![image](https://hackmd.io/_uploads/rJ3hgBJsJx.png)


### Hints

No hint

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/Hyrx-r1iyg.png)

Mở burpsuite và mình thấy được flag trong các request ẩn 

![image](https://hackmd.io/_uploads/ByOQbSJsJx.png)

`Flag: ACECTF{r3d1r3cton}`

## web/Bucket List

![image](https://hackmd.io/_uploads/B1BvWHJo1x.png)

### Hints

No hint

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/H11obrJiJe.png)

Mình thử lùi một bậc vào endpoint /fun xem và không có gì hot cả

![image](https://hackmd.io/_uploads/rJTJMS1i1e.png)

Mình tiếp tục lùi thì có thể thấy ở đây là một file xml chứa các image 

![image](https://hackmd.io/_uploads/r1s6ZSJoke.png)

Tới đây mình thử tìm xem có gì sus không và yeah có một file secret như sau

![image](https://hackmd.io/_uploads/ByzhfBJiyg.png)

Mở file secret và mình thấy một chuỗi trông giống như base64 vậy

![image](https://hackmd.io/_uploads/H1DCGSJsyg.png)

Mình thử decode base64 chuỗi này và có được flag

![image](https://hackmd.io/_uploads/H1t17S1i1l.png)

`Flag: ACECTF{7h3_4w5_15_m15c0nf16ur3d}`
