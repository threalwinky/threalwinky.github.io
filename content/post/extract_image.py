import requests
import sys
import os
import re
import tqdm

if (len(sys.argv) < 2):
    print('No folder found')
    
folder_path = sys.argv[1]
index_path = os.path.join(folder_path, 'index.md')
index_content = open(index_path).read()
pattern = re.compile(r'!\[image\]\((https:\/\/hackmd\.io\/_uploads\/[^)]+)\)')
urls = pattern.findall(index_content)

images_path = os.path.join(folder_path, 'images')

if not os.path.exists(images_path):
    os.makedirs(images_path)
    print(f"Folder '{images_path}' created!")
else:
    print(f"Folder '{images_path}' already exists.")
    
for i in tqdm.tqdm(range(0, len(urls))):
    image_file_name = f'image{str(i)}.png'
    image_file_path = os.path.join(images_path, image_file_name)
    # print(image_file_path)
    r = requests.get(urls[i], stream=True, timeout=10)
    r.raise_for_status()
    with open(image_file_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    
    print(f"Image saved: {image_file_path}")
    index_content = index_content.replace(urls[i], f'./images/{image_file_name}')
# print(index_content)
with open(index_path, 'w') as f:
    f.write(index_content)