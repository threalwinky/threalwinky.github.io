---
title: "TUCTF 2024"
description: "TUCTF 2024"
summary: "TUCTF 2024 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-01-29
draft: false
cover: ../../post/tuctf2024/feature.png
authors:
  - winky
---



## Med Graph

![image](https://hackmd.io/_uploads/Bytzjpwukl.png)

### Solution

Challenge cho ta một trang web như sau

![image](https://hackmd.io/_uploads/HkPEspPuJg.png)

Mình thử đăng nhập với account được đưa ở trong đề bài và reach được đây

![image](https://hackmd.io/_uploads/Hyz8ipvu1g.png)

Khi đăng nhập thì mình có catch được một cái post request như sau. Cho thấy trang web sử dụng GraphQL cho database

![image](https://hackmd.io/_uploads/ByI5o6w_Jx.png)

Đọc source của web thì mình có thấy có file js sau thì mình xác định được mục tiêu là đăng nhập vào với role là doctor, khi đó flag sẽ được hiện ra

```js
async function fetchPatientData() {
    const query = `
        {
            userData {
                name
                age
                medicalHistory
                medications {
                    name
                    dosage
                    description
                }
                doctor {
                    name
                    department
                }
            }
        }
    `;

    const response = await fetch('/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query })
    });

    const result = await response.json();
    displayPatientInfo(result.data.userData);
}

// Render patient and doctor data
function displayPatientInfo(patient) {
    const patientInfo = document.getElementById('patient-info');
    patientInfo.innerHTML = `
        <p>Patient Name: ${patient.name}</p>
        <p>Age: ${patient.age}</p>
        <p>Medical History: ${patient.medicalHistory}</p>
        <p>Medications: ${patient.medications[0].name}, ${patient.medications[0].dosage}</p>
        <p>Doctor: ${patient.doctor.name} (${patient.doctor.department})</p>
    `;
}

async function fetchDoctorData() {
    const query = `
        {
            doctor (id:7892) {
                name
                department
                patients {
                    name
                    age
                    medicalHistory
                    medications {
                        name
                        dosage
                        description
                    }
                }
            }
        }
    `;

    const response = await fetch('/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query })
    });

    const result = await response.json();
    displayDoctorInfo(result.data.doctor);
}

function displayDoctorInfo(doctor) {
    const doctorInfo = document.getElementById('doctor-info');
    doctorInfo.innerHTML = `
    <p>Doctor Name: ${doctor.name}</p>
    <p>Department: ${doctor.department}</p>
    <h3 style="text-align: center;">Patients</h3>
    <hr>
    `;
    for (let patient of doctor.patients) {
        doctorInfo.innerHTML += `
            <p>Patient Name: ${patient.name}</p>
            <p>Age: ${patient.age}</p>
            <p>Medical History: ${patient.medicalHistory}</p>
            <p>Medications: ${patient.medications[0].name}, ${patient.medications[0].dosage}</p>
            <hr>
        `;
    }
}
```

Ok thì đến đây công việc của mình là tìm password của doctor trong database trên. Mình có research thì thấy graphql có một cái để xem cấu trúc của bảng là sử dụng types của __schema

![image](https://hackmd.io/_uploads/HJYShkddyg.png)

Ok thì mình có thể xây dụng một instropection query như sau 

```json
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        description
      }
    }
  }
}
```

Chuyển sang string thì ta có

"{\n__schema {\ntypes {\nname\nkind\ndescription\nfields {\nname\ndescription\n}\n}\n}\n}"

Ok thì sau khi request mình phát hiện có một object có password nên mình nghĩ đây là thằng doctor mình cần tìm

![image](https://hackmd.io/_uploads/BJkQbRvdkx.png)

Bây giờ chỉ cần thêm password vào query thì ta có password của doctor như sau và tên là Ivy

![image](https://hackmd.io/_uploads/Sy6C10w_Jl.png)

e0f109f8bae039c7d27ed30f31985052623349cdcabf2024c2f81b01a8ffaf47

Mình thử đăng nhập thì không được nên tiến hành giải mã các kiểu thì thấy nó đã bị sha256 encode và sau khi decode thì ta có password là madjac

![image](https://hackmd.io/_uploads/S1PKyCDuyx.png)

Ok ngon rồi, mình đăng nhập lại và dã có flag

![image](https://hackmd.io/_uploads/HyS_JCvd1x.png)

## My First Secret

![image](https://hackmd.io/_uploads/S1Pe3RDOke.png)

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SJBOnADu1g.png)

Nhìn vào thì mình biết ngay là sql injection do mình không thấy source đâu :))

Mình thử payload `admin'--` và vào được trang tiếp theo luôn

![image](https://hackmd.io/_uploads/r1hF3ADOJl.png)

Nhìn những ký tự thì mình hết idea luôn nên thử google image search và tìm được link này

https://coppermind.net/wiki/Steel_alphabet

Lúc này mình dựa vào đó và giải mã được chuỗi sau

there is always another secret

Dựa vào yêu cầu đề bài thì mình có flag sau

TUCTF{there_is_always_another_secret}

## Shopping time

![image](https://hackmd.io/_uploads/rk94zydO1x.png)

### Solution

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/Sk8LfJddyg.png)

![image](https://hackmd.io/_uploads/BJj_zku_kl.png)

Source của web : 

<details>
<summary>app.py</summary>
    
```python
from flask import Flask,render_template,request, redirect
import sqlite3
import hashlib

app = Flask(__name__)


@app.route("/")
def mainHandler():
    return render_template("index.html")

@app.route("/review")
def reviewHandler():
    con = sqlite3.connect("shopping.db")
    cur = con.cursor()
    item = request.args.get("item")
    if item == "Flag":
        return("Blacklisted term detected")
    hash = hashlib.md5(item.encode()).hexdigest()
    result = cur.execute("SELECT * FROM items WHERE id=?", (hash[0:6],))
    try:
        result = result.fetchone()
        item = result[1]
    except:
        return (redirect("/"))
    return render_template("review.html",placeholder=item,price=result[2],desc=result[3],img=result[4])


if __name__=="__main__":
    app.run(host="0.0.0.0",port=8000,debug=False)    
```
    
</details>

Có thể thấy những từ mình nhập vào sẽ được md5 encrypt sau đó lấy 6 chữ cái đầu để query nên không thể sql injection gì ở đây được.

Lúc này mình mới nghĩ đến cách brute-force tuy hơi lâu nhưng mà là cách duy nhất rồi :))



```python
import hashlib
import random
import string

def solve(word):
    while True:
        rand = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        hrand = hashlib.md5(rand.encode()).hexdigest()
        if hrand.startswith(word):
            return rand
a="Flag"
b=hashlib.md5(a.encode()).hexdigest()[:6]
c=solve(b)
print(c)
```

Sau khi bruteforce thì mình nhận được chuỗi sau

![image](https://hackmd.io/_uploads/SJn7ByOOkx.png)

Query bằng chuỗi trên và ta có flag

![image](https://hackmd.io/_uploads/BkzBrJ_uyg.png)
