import requests
import urllib.request
from urllib.parse import urlparse
import zipfile
import argparse
import os
import stat
import filetype
import re
import shutil
import magic

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
      elif file_type.mime == 'application/gzip':
        # extract it
        shutil.unpack_archive(filename, target_dir)
      elif file_type.mime in ('application/x-msdownload', 'application/x-executable', 'x-pie-executable', 'x-dos-executable', 'x-dosexec'):
        shutil.copy(filename, target_dir)
      else:
        print(f'[!] Unable to extract release {filename} archive with mime type: {file_type.mime}')
      # delete the zip
      os.remove(filename)
    else:
      print(f'[!] File {filename} didn\'t download to the filepath.')


def make_symlink(target_dir: str, program: str, script_os: str):
  source_file = ''
  target_file = os.path.join(target_dir, f'{program}.exe')
  if os.path.exists(target_file):
    if os.path.islink(target_file):
      os.unlink(target_file)
    else:
      print(f'[!] Target file already exists and is not a symlink, so not creating link.')
      return

  if script_os == 'windows':
    file_type_regex = re.compile('x-(?:dos-executable|dosexec|msdownload)')
    file_mime_regex = re.compile('PE32\\+ executable \\(console\\) x86-64, for MS Windows')
  elif script_os == 'linux':
    file_type_regex = re.compile('x(?:-pie|)-executable|application/x-sharedlib')
    file_mime_regex = re.compile('ELF 64-bit LSB (shared object|pie executable), x86-64')
  else:
    file_type_regex = re.compile('(?:application|x-.*-exec)')
    file_mime_regex = re.compile('x86-64')

  for root, dirs, files in os.walk(target_dir):
    if root.count(os.sep) - target_dir.count(os.sep) < 2:
      for f in files:
        f_path = os.path.join(root, f)
        # check both versions of the mimetype
        file_type = magic.from_file(f_path, mime=True)
        file_mime = magic.from_file(f_path)
        if file_type_regex.search(file_type) and file_mime_regex.search(file_mime):
          print(f'[+] Creating link for: {f_path}, with type: {file_type}. Target file: {target_file}')
          source_file = f_path
          break
  if source_file != '' and source_file != target_file:
    os.symlink(source_file, target_file)
    # make the source executable
    sf_stats = os.stat(source_file)
    os.chmod(source_file, sf_stats.st_mode | 0o774)
    # make the symlink executable
    tf_stats = os.stat(target_file)
    os.chmod(target_file, tf_stats.st_mode | 0o774)
  else:
    print(f'[!] No link created for {program} at path: {target_file}')


def get_release(token: str, url: str, script_os: str):
    repo = urlparse(url).path
    repo = re.sub('\\.git$', '', repo)
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
      else:
        print(f'[ ] Target directory {target_dir} exists, remove the folder if wanting to redownload.')
      # symlink the main .exe to program.exe
      make_symlink(target_dir, program, script_os)
    else:
      print(f'[!] Unable to get the repo from link: {url}')
      print('[ ] Please check the link exists')
      print(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('token', help='your API token')
    parser.add_argument('url', help='the url of the git repo')
    parser.add_argument('script_os', help='the os of the env')
    args = parser.parse_args()

    get_release(args.token, args.url, args.script_os)


if __name__ == '__main__':
  main()
