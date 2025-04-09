---
title: "picoCTF"
description: "picoCTF"
summary: "picoCTF writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-10-10
draft: false
cover: ../../post/picoctf/feature.jpg
authors:
  - winky
---




# PicoCTF Write-ups



| Category | Challenge Name | Difficulty |
| -------- | -------------- | ---------- |
| Web      | findme           | Medium       |
| Web      | JaWT Scratchpad           | Medium       |
| Web      | More SQLi           | Medium       |
| Web      | SOAP          | Medium       |
| Web      | MatchTheRegex          | Medium       |
| Web      | SQLiLite          | Medium       |
| Web      | Who are you?          | Medium       |
| Web      |Some Assembly Required 2          | Medium       |
| Web      |SQL Direct          | Medium       |
| Web      |Some Assembly Required 3          | Hard       |
| Web      |Some Assembly Required 4          | Hard       |

## findme

![](https://hackmd.io/_uploads/HkG-DzagJl.png)

#### Hints
* Bài này để ý vào thanh address sẽ thấy request lạ
* Sử dụng Burpsuite để catch request


#### Solutions
Giao diện website : 
![](https://hackmd.io/_uploads/H1zBKfpx1x.png)
Nhập username và password theo yêu cầu
![](https://hackmd.io/_uploads/B1uLFMTxye.png)
Tiếp tục thoát ra và nhập lại theo yêu cầu
![](https://hackmd.io/_uploads/B1P9FGal1l.png)
Ở ô target của Burpsuite ta catch được 2 request với 2 id lạ
**bF90aGVfd2F5XzI1YmJhZTlhfQ==**
**cGljb0NURntwcm94aWVzX2Fs**
![](https://hackmd.io/_uploads/S1H3FzTx1x.png)
Ta nhận thấy 2 id đã được mã hoá base64 nên ta tiến hành dịch ngược lại 
![](https://hackmd.io/_uploads/SJJScfagJl.png)
Và nhận được flag là picoCTF{proxies_all_the_way_25bbae9a}

## JaWT Scratchpad

![Screenshot 2024-10-25 225121](https://hackmd.io/_uploads/S109cM6gJe.png)


#### Hints
* Bài này sử dụng kĩ thuật tấn công JWT

#### Solutions
Giao diện website : 
![Screenshot 2024-10-26 140516](https://hackmd.io/_uploads/HyWbiGTgkg.png)
Nhập username là admin và bị chặn
![Screenshot 2024-10-26 142201](https://hackmd.io/_uploads/Sku1jGpgJg.png)
Tiếp tục thoát ra và nhập username ngẫu nhiên
![Screenshot 2024-10-26 140624](https://hackmd.io/_uploads/SyUNjGpeJl.png)
Ở cookie ta bắt được jwt của user winky
![Screenshot 2024-10-26 140846](https://hackmd.io/_uploads/r1SBjGTekl.png)
Tiến hành vào trang web [jwt.io](https://jwt.io) để giải mã jwt trên
![Screenshot 2024-10-26 140934](https://hackmd.io/_uploads/SJmOofpxke.png)
Trường payload đang giữ thông tin user nên ta sẽ thay đổi lại user trong payload cũng như tìm secret key 
Tiến hành tìm secret key bằng hashcat và wordlist từ trang web https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
![Screenshot 2024-10-26 142014](https://hackmd.io/_uploads/B1psoMpgJx.png)
sau khi giải mã ta có secretkey ở sau là ilovepico
ta sẽ thay vào trang web vừa nãy để lấy jwt của user admin 
![Screenshot 2024-10-26 142046](https://hackmd.io/_uploads/ryu2jfpe1g.png)
thay jwt này vào devtool để thay đổi user
![Screenshot 2024-10-26 142111](https://hackmd.io/_uploads/Skp3iGal1l.png)
reload lại page và ta có flag : picoCTF{jawt_was_just_what_you_thought_f859ab2f}
![Screenshot 2024-10-26 142131](https://hackmd.io/_uploads/BkeCoMagyg.png)

## More SQLi

![image](https://hackmd.io/_uploads/rJpwvvwNyg.png)

#### Hints

* SQL Injection

#### Solution

Đề bài cho ta một trang đăng nhập sau 

![image](https://hackmd.io/_uploads/SJtuQvD4kx.png)

Mình thử nhập username và password và đi đến trang sau

![image](https://hackmd.io/_uploads/SkrjmwvVyl.png)

Có lẽ là phần password được đưa lên đầu nên mình thử payload mật khẩu sau 

```' OR 1=1 --``` để leak ra tất cả id từ đó đăng nhập vào được

Sau khi đăng nhập thì web đưa ta đến trang welcome sau

![image](https://hackmd.io/_uploads/SJbSNvv4yg.png)

Sau khi nhìn syntax ban nãy ở phần đăng nhập thì mình đoán trang web sử dụng SQLite làm database nên mình thử payload sau để check

```'union select sqlite_version(), null, null--```

![image](https://hackmd.io/_uploads/rJ1vBwvVye.png)

Vậy ta có thể sử dụng sqlite_master để leak tất cả các bảng trong database qua payload sau 

```'union select name, sql, null from sqlite_master--```

![image](https://hackmd.io/_uploads/H1jTSPPEJx.png)

Ta có thể thấy flag nằm trong bảng more_table nên chỉ cần đọc column flag của bảng đó là có được flag
Payload : 

```'union select flag, null, null from more_table--```

![image](https://hackmd.io/_uploads/H14NLvwNke.png)

Flag : picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_e3e46aae}	

## SOAP

![image](https://hackmd.io/_uploads/SJnLDvPN1x.png)

#### Hints 

* XML external entity (XXE) injection

#### Solution 

Đề bài cho mình một trang web sau 

![image](https://hackmd.io/_uploads/rJLcPwDEkg.png)

Sau khi click thử details của một vài trang thì mình nhận được kết quả và request sau

![image](https://hackmd.io/_uploads/HJDawvvE1x.png)

![image](https://hackmd.io/_uploads/rymCDDPEke.png)

Qua đó mình có thể đoán web bị lỗi xxe nên mình giải bài này bằng payload xxe sau 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data><ID>&xxe;</ID></data>
```

Và chúng ta đã có flag

![image](https://hackmd.io/_uploads/BJCQuDvVke.png)

Flag : picoCTF{XML_3xtern@l_3nt1t1ty_0e13660d}

## MatchTheRegex

![image](https://hackmd.io/_uploads/S1OnOvD4Jg.png)

#### Hints

* No hint

#### Solution

Đề bài cho ta một trang web có một input để nhập vào

![image](https://hackmd.io/_uploads/ryXCOPvNkx.png)

Mình thử mở devtools và xem được đoạn script sau dùng để request lên và kiểm tra có match regex **^p.....F!?** không

![image](https://hackmd.io/_uploads/H19CuPwV1l.png)

Ở đây regex này có nghĩa là phần đầu của chuỗi ta nhập phải có dạng "p.....F!?" nên mình cứ nhập lại và thêm bao nhiêu ký tự tuỳ thích thôi, không thêm cũng được :v 

![image](https://hackmd.io/_uploads/SJ5EKwPNye.png)

Flag: picoCTF{succ3ssfully_matchtheregex_f89ea585}

## SQLiLite

![image](https://hackmd.io/_uploads/SkUeqPPV1x.png)

#### Hints

* SQL Injection

#### Solution

Đề bài cho mình trang web sau và yêu cầu đăng nhập 

![image](https://hackmd.io/_uploads/rJ0Z5ww4yg.png)

Mình thử nhập ngẫu nhiên username và password và được redirect tới trang web này 

![image](https://hackmd.io/_uploads/Bk2LcPPN1e.png)

Có lẽ trang web bị dính lỗi SQLi nên mình thử sử dụng payload sau và đăng nhập được

```admin' --```

![image](https://hackmd.io/_uploads/B1btqvvEJe.png)

Ở đây flag đã được giấy nên mình mò thử devtools và có flag 

![image](https://hackmd.io/_uploads/rkEj9wDVyg.png)

Flag: picoCTF{L00k5_l1k3_y0u_solv3d_it_9b0a4e21}

## Who are you?

![image](https://hackmd.io/_uploads/rybHiPDEyg.png)

#### Hints

* Header

#### Solution

Đề bài cho mình trang web sau

![image](https://hackmd.io/_uploads/Bk5LjvP4ye.png)

Web yêu cầu phải sử dụng trình duyệt PicoBrowser nên mình thay đổi lại User agent

```User-Agent: PicoBrowser```

![image](https://hackmd.io/_uploads/BkmrhvPNkg.png)

Tiếp theo mình vẫn bị chặn do không phải là người dùng tin cậy
Có lẽ web muốn request của mình phải có nguồn từ web chính nên thêm header referer vào https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer

```Referer: <url>```

![image](https://hackmd.io/_uploads/SkGE6PPVyg.png)

Tiếp theo vẫn bị chặn do request phải có thời gian là năm 2018. Sau khi search thì mình thấy có header Date sẽ giữ thông tin về thời gian nên mình thêm vào https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date

```Date: Tue, 1 1 2018 1:1:1 GMT```

Sau khi thay vào thì ta tiếp tục bị chặn

![image](https://hackmd.io/_uploads/HJcx0PDVye.png)

Web yêu cầu là user không bị theo dõi. Sau khi tìm hiểu thì chúng ta có header DNT (Do Not Track) có chức năng tuỳ chỉnh nội dung người dùng là private thay vì personalized https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DNT

```DNT: 1```

Sau khi thay vào thì ta tiếp tục bị chặn

![image](https://hackmd.io/_uploads/BJnjAPwNJx.png)

Web yêu cầu request chúng ta phải từ Sweden nên mình tìm thử header liên quan đến địa chỉ và đó là X-Forwarded-For. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For. Sau đó chúng ta cần tìm IP từ sweden trên mạng và thay vào

```X-Forwarded-For: <Sweden IP>```

![image](https://hackmd.io/_uploads/ByhtxODNJg.png)

Sau khi thay vào thì ta tiếp tục bị chặn

![image](https://hackmd.io/_uploads/BJnjAPwNJx.png)

Web yêu cầu request chúng ta phải có language là Swedish nên mình tìm thử header liên quan đến ngồn ngữ và đó là Accept-Language. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language. Chúng ta cần tìm mã language của sweden và đó là sv

```Accept-Language: sv```

![image](https://hackmd.io/_uploads/Hy0Py_vNyl.png)

Sau khi thay vào thì ta có được flag

![image](https://hackmd.io/_uploads/BJiAeOD4yx.png)

Flag: picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_20ace0e4}

## Some Assembly Required 2


![image](https://hackmd.io/_uploads/S1KCbk_Ekg.png)

#### Hints

* Wasm and JS deobfuscation

Bài này theo mình đánh giá là khá hard với mình 

#### Solution

Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/rkN-GkON1e.png)

Sau khi thử bấm một vài thứ thì web trả ra incorret nên mình chuyển qua xem source 

Có thể thấy khi click submit thì event onButtonPress sẽ được trigger

![image](https://hackmd.io/_uploads/SJ4NG1dNye.png)

Xem thử qua các file khác thì mình thấy hàm này ở file Y8splx37qY.js đã được JS obfuscate

![image](https://hackmd.io/_uploads/HyJZau_Eke.png)

<details>
<summary>Y8splx37qY.js</summary>

```js
const _0x6d8f = ['copy_char', 'value', '207aLjBod', '1301420SaUSqf', '233ZRpipt', '2224QffgXU', 'check_flag', '408533hsoVYx', 'instance', '278338GVFUrH', 'Correct!', '549933ZVjkwI', 'innerHTML', 'charCodeAt', './aD8SvhyVkb', 'result', '977AzKzwq', 'Incorrect!', 'exports', 'length', 'getElementById', '1jIrMBu', 'input', '615361geljRK'];
const _0x5c00 = function(_0x58505a, _0x4d6e6c) {
    _0x58505a = _0x58505a - 0xc3;
    let _0x6d8fc4 = _0x6d8f[_0x58505a];
    return _0x6d8fc4;
};
(function(_0x12fd07, _0x4e9d05) {
    const _0x4f7b75 = _0x5c00;
    while (!![]) {
        try {
            const _0x1bb902 = -parseInt(_0x4f7b75(0xc8)) * -parseInt(_0x4f7b75(0xc9)) + -parseInt(_0x4f7b75(0xcd)) + parseInt(_0x4f7b75(0xcf)) + parseInt(_0x4f7b75(0xc3)) + -parseInt(_0x4f7b75(0xc6)) * parseInt(_0x4f7b75(0xd4)) + parseInt(_0x4f7b75(0xcb)) + -parseInt(_0x4f7b75(0xd9)) * parseInt(_0x4f7b75(0xc7));
            if (_0x1bb902 === _0x4e9d05)
                break;
            else
                _0x12fd07['push'](_0x12fd07['shift']());
        } catch (_0x4f8a) {
            _0x12fd07['push'](_0x12fd07['shift']());
        }
    }
}(_0x6d8f, 0x4bb06));
let exports;
(async () => {
    const _0x835967 = _0x5c00;
    let _0x1adb5f = await fetch(_0x835967(0xd2))
      , _0x355961 = await WebAssembly['instantiate'](await _0x1adb5f['arrayBuffer']())
      , _0x5c0ffa = _0x355961[_0x835967(0xcc)];
    exports = _0x5c0ffa[_0x835967(0xd6)];
}
)();
function onButtonPress() {
    const _0x50ea62 = _0x5c00;
    let _0x5f4170 = document[_0x50ea62(0xd8)](_0x50ea62(0xda))[_0x50ea62(0xc5)];
    for (let _0x19d3ca = 0x0; _0x19d3ca < _0x5f4170['length']; _0x19d3ca++) {
        exports[_0x50ea62(0xc4)](_0x5f4170[_0x50ea62(0xd1)](_0x19d3ca), _0x19d3ca);
    }
    exports['copy_char'](0x0, _0x5f4170[_0x50ea62(0xd7)]),
    exports[_0x50ea62(0xca)]() == 0x1 ? document['getElementById'](_0x50ea62(0xd3))[_0x50ea62(0xd0)] = _0x50ea62(0xce) : document[_0x50ea62(0xd8)](_0x50ea62(0xd3))['innerHTML'] = _0x50ea62(0xd5);
}
```
    
</details>
    
Ok thì mình sẽ tiến hành deobfuscate file này. Đầu tiên mình sẽ thay các hex value bằng tên để cho dễ đọc
    
<details>
<summary>Y8splx37qY.js</summary>

```js
const array = ['copy_char', 'value', '207aLjBod', '1301420SaUSqf', '233ZRpipt', '2224QffgXU', 'check_flag', '408533hsoVYx', 'instance', '278338GVFUrH', 'Correct!', '549933ZVjkwI', 'innerHTML', 'charCodeAt', './aD8SvhyVkb', 'result', '977AzKzwq', 'Incorrect!', 'exports', 'length', 'getElementById', '1jIrMBu', 'input', '615361geljRK'];

const get_array_value = function(index, _0x4d6e6c) {
    index = index - 195;
    let array_value = array[index];
    return array_value;
};

(function(a, b) {
    const g1 = get_array_value;
    while (!![]) {
        try {
            const value = -parseInt(g1(200)) * -parseInt(g1(201)) + -parseInt(g1(205)) + parseInt(g1(207)) + parseInt(g1(195)) + -parseInt(g1(198)) *  parseInt(g1(212)) + parseInt(g1(203)) + -parseInt(g1(217)) *  parseInt(g1(199));
            if (value === b)
                break;
            else
                a['push'](a['shift']());
        } catch (_0x4f8a) {
            a['push'](a['shift']());
        }
    }
}(array, 310022));
let exports;
(async () => {
    const g2 = get_array_value;
    let f = await fetch(g2(210))
      , wasm = await WebAssembly['instantiate'](await f['arrayBuffer']())
      , res = wasm[g2(204)];
    exports = res[g2(214)];
}
)();

function onButtonPress() {
    const g3 = get_array_value;
    let input = document[g3(216)](g3(218))[g3(197)];
    for (let i = 0; i < input['length']; i++) {
        exports[g3(196)](input[g3(209)](i), i);
    }
    exports['copy_char'](0, input[g3(215)]),
    exports[g3(202)]() == 1 ? document['getElementById'](g3(211))[g3(208)] = g3(206) : document[g3(216)](g3(211))['innerHTML'] = g3(213);
}
```
    
</details>
    
Ngó qua hàm thứ 2 thấy có sử dụng mảng array làm param nên mình nghĩ sẽ có thay đổi gì đó trong mảng. Mình thực hiện debug trước và sau khi hàm chạy và nhận được kết quả sau 
    
![image](https://hackmd.io/_uploads/B1XDmy_N1x.png)

Ok và mình đã đúng, và chúng ta có mảng array mới như sau và bỏ được hàm thay đổi đó
    
<details>
<summary>Y8splx37qY.js</summary>

```js
const array =[
    '615361geljRK',  'copy_char',
    'value',         '207aLjBod',
    '1301420SaUSqf', '233ZRpipt',
    '2224QffgXU',    'check_flag',
    '408533hsoVYx',  'instance',
    '278338GVFUrH',  'Correct!',
    '549933ZVjkwI',  'innerHTML',
    'charCodeAt',    './aD8SvhyVkb',
    'result',        '977AzKzwq',
    'Incorrect!',    'exports',
    'length',        'getElementById',
    '1jIrMBu',       'input'
  ]

const get_array_value = function(index, _0x4d6e6c) {
    index = index - 195;
    let array_value = array[index];
    return array_value;
};

let exports;
(async () => {
    const g2 = get_array_value;
    let f = await fetch(g2(210))
      , wasm = await WebAssembly['instantiate'](await f['arrayBuffer']())
      , res = wasm[g2(204)];
    exports = res[g2(214)];
}
)();

function onButtonPress() {
    const g3 = get_array_value;
    let input = document[g3(216)](g3(218))[g3(197)];
    for (let i = 0; i < input['length']; i++) {
        exports[g3(196)](input[g3(209)](i), i);
    }
    exports['copy_char'](0, input[g3(215)]),
    exports[g3(202)]() == 1 ? document['getElementById'](g3(211))[g3(208)] = g3(206) : document[g3(216)](g3(211))['innerHTML'] = g3(213);
}
```
    
</details>
    
Tiếp theo mình thay các giá trị trong array vào thông qua hàm get_array_value và mình có được đoạn code trông clean hơn lúc đầu như sau
    
<details>
<summary>Y8splx37qY.js</summary>
    
```js
let exports;
(async () => {
    let f = await fetch("./aD8SvhyVkb")
      , wasm = await WebAssembly.instantiate(await f.arrayBuffer())
      , res = wasm.instance;
    exports = res.exports;
}
)();

function onButtonPress() {
    let input = document.getElementById.input("value");
    for (let i = 0; i < input.length; i++) {
        exports.copy_char(input.charCodeAt(i), i);
    }
    exports.copy_char(0, input.length),
    exports.check_flag() == 1 ? document.getElementById("result").innerHTML = "Correct!" : document.getElementById("result").innerHTML = "Incorrect!";
}
```
    
</details>

Phân tích về luồng chạy của hàm trên : 

* Đầu tiên khai báo biến exports
* Biến f sẽ fetch endpoint ./aD8SvhyVkb để lấy nội dung gì đó mình nghĩ đây sẽ là wasm vì sau đó biến wasm tiến hành decompile file đó và lấy các wasm.instance.exports để gắn vào exports
* Khi button submit được click, input của người dùng được đưa vào export thông qua hàm copy_char của wasm
* Cuối cùng hàm check_flag của wasm sẽ check xem có trùng với flag không và trả ra kết quả tương ứng
    
Qua đó, mình thử tải về file aD8SvhyVkb để tiến hành decompile
    
![image](https://hackmd.io/_uploads/rk2cc__EJe.png)
    
Mình sẽ sử dụng một tool khá ngon của ghidra để chuyển binary wasm sang code c 
https://github.com/nneonneo/ghidra-wasm-plugin
    
![image](https://hackmd.io/_uploads/ryDi9ddV1e.png)

Sau khi decompile thì mình nhận được 2 hàm là copy_char và check_flag như sau, có 1 hàm str_cmp nữa nhưng chắc chỉ là so sánh 2 sring nên mình bỏ qua    

![image](https://hackmd.io/_uploads/BykR9_dEkx.png)

![image](https://hackmd.io/_uploads/rJQkidO41x.png)

Phân tích : 
* Hàm copy_char sẽ lấy mã ascii của char và xor với 8 sau đó gán vào vị trí tương ứng trên địa chỉ 0x430 + param2(ở code js là vị trí của char)
* Hàm check_flag sẽ so sánh char* ở hai địa chỉ 0x400 và 0x430 nhưng vì 0x430 là input của mình ở trên nên chắc chắn flag nằm ở 0x400
* Xem thử ở vị trí 0x400 và mình thấy có một chuỗi kí tự như sau: 
    
![image](https://hackmd.io/_uploads/SJX-su_Vkl.png)

Vì đây là các kí tự sau khi input được xor 8 nên mình tiến thành decode lại bằng cách xor 8. it works because a xor b = c so a xor c = b. Đây là đoạn code decrypt của mình bằng python sau khi chạy thì ta có flag như sau
    
```python
s = "xakgK\\Ns>n;jl90;9:mjn9m<0n9::0::881<00?>u"
r = ""
for i in s:
    r += chr(ord(i) ^ 8)
print(r)
```    

![image](https://hackmd.io/_uploads/HkK_WYO4yx.png)

Flag : picoCTF{6f3bd18312ebf1e48f12282200948876}
    
P/S: Bài này mình dành 1 thời gian khá lâu mới giải được và đây là số lượng file mình đã tạo ra 🐧
    
![image](https://hackmd.io/_uploads/SJXSfFuVyx.png)

## SQL Direct
    
![image](https://hackmd.io/_uploads/rJqertZDyl.png)
    
#### Hints
    
No hints
    
#### Solution
    
Đầu tiên khi vào database thì mình thử list các bảng hiện có và phát hiện có bằng flags
    
![image](https://hackmd.io/_uploads/BkI-SYZD1l.png)

Bây giờ chỉ việc list hết các item của bảng flags là xong 
    
`SELECT * FROM flags;`

![image](https://hackmd.io/_uploads/HJRzBFZDJg.png)

Flag: picoCTF{L3arN_S0m3_5qL_t0d4Y_73b0678f}

## Some Assembly Required 3
    
![image](https://hackmd.io/_uploads/rkfYIXauye.png)
    
#### Hints
    
Wasm and JS deobfuscation
    
#### Solution
    
Bài này khá giống version 2 và challenge cho mình một trang web như sau
    
![image](https://hackmd.io/_uploads/H1ggDQpuJg.png)

Vào devtool thì mình phát hiện có file này nên mình thử deobfuscate xem 
    
![image](https://hackmd.io/_uploads/rytZvmpOyx.png)

<details>

<summary>rTEuOmSfG3.js</summary>
    
```js
const _0x143f = ['exports', '270328ewawLo', 'instantiate', '1OsuamQ', 'Incorrect!', 'length', 'copy_char', 'value', '1512517ESezaM', 'innerHTML', 'check_flag', 'result', '1383842SQRPPf', '924408cukzgO', 'getElementById', '418508cLDohp', 'input', 'Correct!', '573XsMMHp', 'arrayBuffer', '183RUQBDE', '38934oMACea'];
const _0x187e = function(_0x3075b9, _0x2ac888) {
    _0x3075b9 = _0x3075b9 - 0x11d;
    let _0x143f7d = _0x143f[_0x3075b9];
    return _0x143f7d;
};
(function(_0x3379df, _0x252604) {
    const _0x1e2b12 = _0x187e;
    while (!![]) {
        try {
            const _0x5e2d0a = -parseInt(_0x1e2b12(0x122)) + -parseInt(_0x1e2b12(0x12f)) + -parseInt(_0x1e2b12(0x126)) * -parseInt(_0x1e2b12(0x12b)) + -parseInt(_0x1e2b12(0x132)) + parseInt(_0x1e2b12(0x124)) + -parseInt(_0x1e2b12(0x121)) * -parseInt(_0x1e2b12(0x11f)) + parseInt(_0x1e2b12(0x130));
            if (_0x5e2d0a === _0x252604)
                break;
            else
                _0x3379df['push'](_0x3379df['shift']());
        } catch (_0x289152) {
            _0x3379df['push'](_0x3379df['shift']());
        }
    }
}(_0x143f, 0xed04c));
let exports;
(async () => {
    const _0x484ae0 = _0x187e;
    let _0x487b31 = await fetch('./qCCYI0ajpD')
      , _0x5eebfd = await WebAssembly[_0x484ae0(0x125)](await _0x487b31[_0x484ae0(0x120)]())
      , _0x30f3ed = _0x5eebfd['instance'];
    exports = _0x30f3ed[_0x484ae0(0x123)];
}
)();
function onButtonPress() {
    const _0x271e58 = _0x187e;
    let _0x441124 = document[_0x271e58(0x131)](_0x271e58(0x11d))[_0x271e58(0x12a)];
    for (let _0x34c54a = 0x0; _0x34c54a < _0x441124[_0x271e58(0x128)]; _0x34c54a++) {
        exports[_0x271e58(0x129)](_0x441124['charCodeAt'](_0x34c54a), _0x34c54a);
    }
    exports[_0x271e58(0x129)](0x0, _0x441124[_0x271e58(0x128)]),
    exports[_0x271e58(0x12d)]() == 0x1 ? document[_0x271e58(0x131)](_0x271e58(0x12e))[_0x271e58(0x12c)] = _0x271e58(0x11e) : document[_0x271e58(0x131)](_0x271e58(0x12e))['innerHTML'] = _0x271e58(0x127);
}    
```
    
</details>
    
<details>

<summary>rTEuOmSfG3.js</summary>
    
```js
let exports;
(async () => {
    const _0x484ae0 = _0x187e;
    let _0x487b31 = await fetch('./qCCYI0ajpD')
      , _0x5eebfd = await WebAssembly.instantiate(await _0x487b31.arrayBuffer())
      , _0x30f3ed = _0x5eebfd['instance'];
    exports = _0x30f3ed.exports;
}
)();
function onButtonPress() {
    const _0x271e58 = _0x187e;
    let _0x441124 = document.getElementById('input').value;
    for (let _0x34c54a = 0x0; _0x34c54a < _0x441124.length; _0x34c54a++) {
        exports.copy_char(_0x441124['charCodeAt'](_0x34c54a), _0x34c54a);
    }
    exports.copy_char(0, _0x441124.length),
    exports.check_flag() == 0x1 ? document.getElementById('result').innerHTML = "Correct" : document.getElementById('result')['innerHTML'] = "False";
```
    
</details>
    
Sau khi deobfuscate thì mình thấy được web sẽ lấy code từ file ./qCCYI0ajpD nên mình tiến hành tải về và dịch như version trước
    
![image](https://hackmd.io/_uploads/Hyzsw76_1e.png)

Đến đây có một đoạn khác là input mình nhập vào sẽ được xor với một giá trị nào đó gần với địa chỉ 0x42f. Và cuối cùng check với 0x400 như trong hàm check_flag.
    
![image](https://hackmd.io/_uploads/Skw3wXadyx.png)

Đến đây thì mình xem 0x400 có các giá trị sau
    
![image](https://hackmd.io/_uploads/H1q6wQpOyl.png)

và 0x42f cũng có những giá trị sau
    
![image](https://hackmd.io/_uploads/HJtAPX6Oyx.png)

Từ đó mình có thể xây dựng solve script như sau
    
```python
a = ["ed", "07", "f0", "a7", "f1"]

s = ""

b = ["9d", "6e", "93", "c8", "b2", "b9", "41", "8b", "c1", "c5", "dc", "61", "c6", "97", "94", "8c", "66", "91", "91", "c1", "89", "33", "94", "9e", "c9", "dd", "61", "91", "c4", "c8", "dd", "62", "c0", "92", "c1", "8c", "37", "95", "93", "c8", "90"]


for i in range(0, len(b)):

    s += (chr(int(b[i], 16) ^ int(a[i%5], 16)))

print(s)    
```
    
Khi chạy thì chúng ta có flag

![image](https://hackmd.io/_uploads/Sy-xOQadyx.png)

picoCTF{f41f60eaaa60d4d980fac90e050a0e49}
    
## Some Assembly Required 4
    
![image](https://hackmd.io/_uploads/Bko9D4aO1e.png)
    
#### Hints
    
Brute force, Wasm and JS deobfuscation
    
#### Solution
    
Như các version trước thì mình cũng nhận được một file wasm nên mình tiến hành decompile nó. Đến đây mình nhận được một hàm khá phức tạp.
    
![image](https://hackmd.io/_uploads/BJo3vEa_yl.png)


    
![image](https://hackmd.io/_uploads/BJPgON6O1x.png)

Sau khi đọc kỹ hàm thì mình nhận ra có thể brute force được flag vì với mỗi chữ cái thì ta cần quan tâm giá trị s[i-3] và s[i-1] thôi nhưng mà trong flag chúng ta đã biết chữ pico ở đầu rồi.
    
```c
byte export::check_flag(void)

{
  undefined uVar1;
  int iVar2;
  int local_c;
  byte local_5;
  int local_4;
  
  for (local_4 = 0; *(char *)(local_4 + 0x430) != '\0'; local_4 = local_4 + 1) {
    *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 0x14;
    if (0 < local_4) {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ *(byte *)(local_4 + 0x42f);
    }
    if (2 < local_4) {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ *(byte *)(local_4 + 0x42d);
    }
    *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ (byte)(local_4 % 10);
    if (local_4 % 2 == 0) {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 9;
    }
    else {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 8;
    }
    if (local_4 % 3 == 0) {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 7;
    }
    else if (local_4 % 3 == 1) {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 6;
    }
    else {
      *(byte *)(local_4 + 0x430) = *(byte *)(local_4 + 0x430) ^ 5;
    }
  }
  for (local_c = 0; local_c < local_4; local_c = local_c + 1) {
    if ((local_c % 2 == 0) && (local_c + 1 < local_4)) {
      uVar1 = *(undefined *)(local_c + 0x430);
      *(undefined *)(local_c + 0x430) = *(undefined *)(local_c + 0x431);
      *(undefined *)(local_c + 0x431) = uVar1;
    }
  }
  iVar2 = strcmp((char *)0x400,(char *)0x430);
  return (iVar2 != 0 ^ 0xffU) & 1;
}   
```
    
Qua đó ta có thể xây dựng solve script dùng để brute force như sau : 
    
```python
import string

a = ["18","6a","7c","61","11","38","69","37","1e","5f","7d","5b","68","4b","5d","3d","02","18","14","7b","65","36","45","5d","28","5c","33","45","09","39","56","44","42","7d","3b","6f","40","57","7f","0e","59"]

for i in range(0, len(a)):
    if (i % 2 == 0 and i < len(a) - 1):
        tmp = a[i]
        a[i] = int(a[i+1], 16)
        
        a[i+1] = int(tmp, 16)

s = ["p", "i", "c", "o"]

# print(a)

for i in range(0, 4):
    c_n = ord(s[i])
    c_n ^= 20
    if (i > 0):
        c_n ^= ord(s[i-1])
    if (i > 2):
        c_n ^= ord(s[i-3])
    c_n ^= (i % 10)
    if (i % 2 == 0):
        c_n ^= 9
    else:
        c_n ^= 8
    if (i % 3 == 0):
        c_n ^= 7
    elif (i % 3 == 1):
        c_n ^= 6
    else:
        c_n ^= 5
    s[i] = chr(c_n)

patt = string.printable

flag = "pico"

for i in range(4, len(a)):
    for c in patt:
        c_n = ord(c)
        c_n ^= 20
        c_n ^= ord(s[i-1])
        c_n ^= ord(s[i-3])
        c_n ^= (i % 10)
        if (i % 2 == 0):
            c_n ^= 9
        else:
            c_n ^= 8
        if (i % 3 == 0):
            c_n ^= 7
        elif (i % 3 == 1):
            c_n ^= 6
        else:
            c_n ^= 5
        if (c_n == a[i]):
            flag += c
            # print(s)
            s.append(chr(c_n))

print(flag)    
```
    
Sau khi chạy thì chúng ta có flag
    
![image](https://hackmd.io/_uploads/HJXEuNadJx.png)

Flag : picoCTF{7d7a0a45096d8254b6661ed08cd52ee4}