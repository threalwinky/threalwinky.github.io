---
title: "WannaGame Championship 2024"
description: "WannaGame Championship 2024"
summary: "WannaGame Championship 2024 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-12-14
draft: false
cover: ../../post/w1champ2024/feature.png
authors:
  - winky
---

## re gekco 

![image](https://hackmd.io/_uploads/BkQo7BsE1l.png)

#### Source

https://drive.google.com/file/d/10SJuyHYi2WXhhY2DworT6LGPVQHWp3jv/view?usp=sharing

#### Hints

* CR-LF injection and path traversal

#### Solution

Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/HJPY4SjVJg.png)

Sau khi đọc source thì đây là 3 file mình cần lưu ý

<details>
<summary>docker-compose.yml</summary>
    
```yml
version: '3'

services:
  re-gecko:
    build:
      context: ./nginx
    ports:
      - 8001:80
    restart: always
    volumes:
      - ./flag:/flag
  inner:
    build:
      context: ./inner
```
    
</details>

<details>
<summary>nginx.conf</summary>
    
```nginx
user nginx;

worker_processes 4;

events {
    use epoll;
    worker_connections 128;
}

http {
    charset utf-8;

    access_log /dev/stdout combined;
    error_log /dev/stdout debug;

    upstream @inner {
        server inner:3000;
    }
    server {
        listen 80;
        server_name _;

        location ~* ^(.*)$ {
            return 200 "i catch you!";
        }

        location / {
            add_header X-Original "$uri";
            return 200 "I Catch You!";
        }

        location /firefly {
            proxy_pass http://@inner$uri$is_args$args;
        }
    }
# http://inner:3000/aaa
    server {
        listen 8082;
        server_name flagg;
        include flags.conf;

        location /firefly {
            return 200 "Just look at the sky, you will see ....";
        }

         location /firefly/jxx {
            add_header X-Origin "$uri";
            return 200 ".. you will see a star named ...";
        }

        
        location /inner {
            return 200 "nothing here for you, you wanna know star's name????";
        }

        location /flag {
            return 200 "$flag";
        }
    }

}
```
    
</details>

<details>
<summary>index.js</summary>
    
```js
const express = require('express');
const http = require('http');
const app = express();
// exp remote pls change re-gecko to service
const RE_GECKO_URL = process.env.RE_GECKO_URL || 'http://re-gecko:8082/';

app.use(express.json());

app.all('*', async (req, res) => {
  try {
    var { method, path, body, headers } = req;
    console.log(method,path,body, headers)
    console.log(path)
     path = path.startsWith('/') ? path.slice(1) : path;
    console.log(path)
    const checkvar = (path) => {
        try {
          if (!path) throw new Error("no path");
          const regex = new RegExp(/^[A-z0-9.\s_-]+$/i);
          if (regex.test(path)) {
            const checked_path = path.replaceAll(/\s/g, "");
            return checked_path;
          } else {
            throw new Error("Error!!");
          }
        } catch (e) {
          console.log(e);
          return "something went wrong";
        }
        };
      path = checkvar(path)
      path = path;

      var re = /flag/i;
      if (re.exec(path)) {
          path = path.replace(re, "");
      }
      
      let url   = new URL(path, RE_GECKO_URL);
    
      const options = {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        headers: { ...headers, host: url.hostname },
      };
  
      const request = http.request(options, (response) => {
        let data = '';
        response.on('data', (chunk) => {
          data += chunk;
        });
        response.on('end', () => {
          res.status(response.statusCode).send(data);
        });
      });
  
      request.on('error', (error) => {
        console.error('Error forwarding request:', error.message);
        res.status(500).send({ error: 'Failed to forward request' });
      });

  
      request.end();
    } catch (error) {
      console.error('Error forwarding request:', error.message);
      res.status(500).send({ error: 'Failed to forward request' });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Node.js forwarding service is running on port ${PORT}`);
});
```
    
</details>

Phân tích : 

* Trang web có 2 service là re-gecko và inner trong đó chỉ có re-gecko được expose ở port 8001 trả ra kết quả như trên. 
* Nhiệm vụ của mình sẽ là truy cập vào endpoint /flag của server inner để lấy được flag. Nhưng phải làm thế nào?
* Đầu tiên chúng ta có thể thấy endpoint /firefly của gecko được proxy_pass đến ```http://@inner$uri$is_args$args``` trong đó ```@inner``` là server inner mình cần truy cập đến để lấy flag, ```$uri``` là uri của header X-Original sau khi đi qua location / và ```$is_args$args``` để lấy params của request
* OK từ đó mình có ý tưởng là sẽ sử dụng endpoint /firefly đi qua location / để lấy $uri, tiếp đến ta proxy_pass đến @inner/firefly sau đó thực hiện path traversal qua /firefly/jxx để lấy header X-Origin và cuối cùng trở về /flag

OK đầu tiên mình thử request đến /firefly và nhận được kết quả sau

![image](https://hackmd.io/_uploads/Sk-jeLjEyl.png)

Có thể thấy endpoint bị dính regex của location đầu tiên và trả ra i catch you. Vậy làm sao để bypass và qua được location / ? Thì mình có thể sử dụng CR-LF injection bằng cách thêm các ký tự %0A(new line) và %0D(carriage return) để insert một line trên firefly từ đó bypass được regex

![image](https://hackmd.io/_uploads/Hygy-UsNJx.png)

OK và ta đã proxy_pass qua được server inner. Vậy bây giờ ta chỉ cần path traversal thôi mình sẽ thử payload sau để vào /jxx

/firefly/../firefly/jxx%0a%0d

![image](https://hackmd.io/_uploads/HyBM-LoEyx.png)

Well... Kết quả trả ra 404, mình thử đọc thử source code js thì nó có một đoạn check regex sau ```const regex = new RegExp(/^[A-z0-9.\s_-]+$/i);``` qua đó mình không thể sử dụng / trong url được và % cũng không. Vậy không có cách nào bypass ư? Khoan... Nhìn kĩ lại regex thì nó lấy cả characters từ A-z có nghĩa là lấy luôn cả \ trong bảng ASCII 

![image](https://hackmd.io/_uploads/HkbL0rj41e.png)

Từ đó mình có thể thay / bằng \ thế là lại path traversal được thôi 😎 Mình thử test với payload sau

/firefly\\\..\firefly\jxx%0a%0d

![image](https://hackmd.io/_uploads/HkkVb8iVyg.png)

Bumppph, it works. So now, mình chỉ cần redirect tới flag thôi. Cơ mà, phải lưu ý có đoạn replace regex chữ flag nên mình chỉ cần bypass bằng flflagag, ez man

/firefly\\\..\firefly\jxx\\\..\\\..\flflagag%0a%0d

![image](https://hackmd.io/_uploads/ryytb8iVye.png)

Ok và mình có flag ở local. Bây giờ chỉ cần submit lên remote là xong 

![image](https://hackmd.io/_uploads/SkEwG8jNyx.png)

Flag : W1{gud_job_bro_e54b01b73a966f9315913357ceb98305}