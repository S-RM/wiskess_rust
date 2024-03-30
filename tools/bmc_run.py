"""
Run BMC Tools

Author: Gavin Hull
Version: 0.0.1

This is a wrapper around bmc_tools, where it creates a folder from the path of
where the cache files are stored, i.e. if at Users/joe/AppData/Local/Microsoft/Terminal Server Client/Cache/Cache0002.bin
it creates a folder Network/joe_rdp_bitmap, and runs bmc_tools with that as the dest
"""

import os
import argparse
import re
import subprocess

def mkdir(path):
    try:
      os.mkdir(path)
      print("Directory created successfully!")
    except FileExistsError:
      print("Directory already exists!")
    except OSError as e:
      print(f"Error creating directory: {e}")

def run_bmc(src, dst, script_path):
    user = re.search(r'Users[\\/]([^\\/]+)', src)
    if user:
        user_folder = f'{user.group(1)}_rdp-bitmap'
        out_path = os.path.join(dst, user_folder)
        mkdir(out_path)
        args = ["-s", src, "-d", out_path, "-b"]
        subprocess.run(["python3", script_path] + args)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bitmap_path') # input
    parser.add_argument('out_path') # outfolder
    parser.add_argument('script_path') # tool_path + script path
    args = parser.parse_args()

    # {tool_path}/bmc-tools/bmc-tools.py -s {input} -d {outfolder} -b
    run_bmc(args.bitmap_path, args.out_path, args.script_path)


if __name__ == '__main__':
  main()
