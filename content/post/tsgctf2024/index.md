---
title: "TSG CTF 2024"
description: "TSG CTF 2024"
summary: "TSG CTF 2024 writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-12-15
draft: false
cover: ../../post/tsgctf2024/feature.png
authors:
  - winky
---


## Toolong tea

![image](https://hackmd.io/_uploads/ByUz0w341g.png)

#### Source

https://drive.google.com/file/d/1e8EKn0oWDwhx2dvTnD87heEfQ3ZvO2Wr/view?usp=sharing

#### Hints

* Array parseInt

#### Solution

Đề bài cho mình một trang web như sau

![image](https://hackmd.io/_uploads/H1sw0v3NJg.png)

Source : 

```js
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";

const flag = process.env.FLAG ?? "TSGCTF{DUMMY}";

const app = new Hono();

app.get("*", serveStatic({ root: "./public" }));

app.post("/", async (c) => {
	try {
		const { num } = await c.req.json();
		if (num.length === 3 && [...num].every((d) => /\d/.test(d))) {
			const i = parseInt(num, 10);
			if (i === 65536) {
				return c.text(`Congratulations! ${flag}`);
			}
			return c.text("Please send 65536");
		}
		if (num.length > 3) {
			return c.text("Too long!");
		}
		return c.text("Please send 3-digit integer");
	} catch {
		return c.text("Invalid JSON", 500);
	}
});

serve({
	fetch: app.fetch,
	port: 4932,
});
```

Phân tích : 
* Biến num được truyền vào lấy từ json của request và sau đó được check length = 3 và regex tất cả phải là chữ số 
* Sau đó num sẽ được parseInt vào biến i và xem có phải là số 65536 không nếu có thì sẽ trả ra flag
* Từ đó, mình nghĩ là không thể nào truyền một biến string được vì '65536' không phải length 3 nên mình nghĩ đến việc truyền một array. Vì sao lại thế ? Theo document của hàm parseInt, khi truyền vào  một mảng thì nó sẽ lấy phần tử đầu để chuyển đổi.

![image](https://hackmd.io/_uploads/HkJlldnV1e.png)

* Qua đó, ta có thể dưa số 65536 vào một mảng có 3 phần tử và dễ dàng bypass được hàm check length lẫn hàm check số. Thêm nữa khi truyền vào một mảng toàn số cũng sẽ bypass được hàm regex do nó sẽ bung hết giá trị số trong mảng đó ra.

![image](https://hackmd.io/_uploads/BkvCMdnN1g.png)

Flag : TSGCTF{A_holy_night_with_no_dawn_my_dear...}