import asyncio
import httpx
import os
import re
import sys
from tqdm.asyncio import tqdm_asyncio


async def download_image(client, url, image_file_path):
    try:
        async with client.stream("GET", url, timeout=10) as r:
            r.raise_for_status()
            with open(image_file_path, "wb") as f:
                async for chunk in r.aiter_bytes(chunk_size=8192):
                    f.write(chunk)
        return image_file_path
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return None


async def main():
    if len(sys.argv) < 2:
        print("No folder found")
        return

    folder_path = sys.argv[1]
    index_path = os.path.join(folder_path, "index.md")
    index_content = open(index_path).read()

    pattern = re.compile(r"!\[image\]\((https:\/\/hackmd\.io\/_uploads\/[^)]+)\)")
    urls = pattern.findall(index_content)

    images_path = os.path.join(folder_path, "images")
    os.makedirs(images_path, exist_ok=True)
    print(f"Folder '{images_path}' ready.")

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = []
        for i, url in enumerate(urls):
            image_file_name = f"image{i}.png"
            image_file_path = os.path.join(images_path, image_file_name)
            tasks.append(download_image(client, url, image_file_path))
            index_content = index_content.replace(url, f"./images/{image_file_name}")

        results = []
        for coro in tqdm_asyncio.as_completed(tasks, total=len(tasks), desc="Downloading"):
            res = await coro
            if res:
                results.append(res)

    with open(index_path, "w") as f:
        f.write(index_content)

    print(f"Downloaded {len(results)}/{len(urls)} images successfully!")


if __name__ == "__main__":
    asyncio.run(main())
