import requests
import urllib.request
from urllib.parse import urlparse
import zipfile
import argparse
import os
import filetype
import re
import shutil

def get_files(response: str, target_dir: str):
  # download each url, and extract, then delete the zip
  for url in response.json()['assets']:
    print(url['browser_download_url'])
    filename = url['name']
    urllib.request.urlretrieve(url['browser_download_url'], filename)
    if os.path.exists(filename):
      file_type = filetype.guess(filename)
      if file_type is None:
        print(f'[!] No file type known for file: {filename}')
        os.remove(filename)
        continue
      elif file_type.mime == 'application/zip':
        # extract it
        with zipfile.ZipFile(filename, 'r') as zip_ref:
          zip_ref.extractall(target_dir)
      elif file_type.mime in ('application/x-msdownload', 'application/x-executable'):
        shutil.copy(filename, target_dir)
      else:
        print(f'[!] Unable to extract release {filename} archive with mime type: {file_type.mime}')
      # delete the zip
      os.remove(filename)
    else:
      print(f'[!] File {filename} didn\'t download to the filepath.')


def make_symlink(target_dir: str, program: str):
  source_file = ''
  target_file = os.path.join(target_dir, f'{program}.exe')
  if os.path.exists(target_file):
    return
  for root, dirs, files in os.walk(target_dir):
    if root.count(os.sep) - target_dir.count(os.sep) < 2:
      for f in files:
        if re.match(r'.*\.exe$', f):
          source_file = os.path.join(root, f)
          break
  if source_file != '' and source_file != target_file:
    os.symlink(source_file, target_file)
        

def get_release(token: str, url: str):
    repo = urlparse(url).path
    repo = re.sub('\.git$', '', repo)
    program = repo.split('/')[-1]

    headers = {
      'Accept': 'application/vnd.github+json',
      'Authorization': f'Bearer {token}',
      'X-GitHub-Api-Version': '2022-11-28',
    }

    response = requests.get(f'https://api.github.com/repos{repo}/releases/latest', headers=headers)

    if response.status_code == 200:
      # make dir from file stub and copy file there
      target_dir = os.path.join(os.getcwd(), program)
      if not os.path.exists(target_dir):
        os.makedirs(target_dir)
      # download the files to target dir
      get_files(response, target_dir)
      # symlink the main .exe to program.exe
      make_symlink(target_dir, program)
    else:
      print(f'[!] Unable to get the repo from link: {url}')
      print('[ ] Please check the link exists')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('token', help='your API token')
    parser.add_argument('url', help='the url of the git repo')
    args = parser.parse_args()

    get_release(args.token, args.url)
    

if __name__ == '__main__':
  main()  