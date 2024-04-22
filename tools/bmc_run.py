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
import glob
import importlib

def mkdir(path):
    try:
      os.mkdir(path)
      print("Directory created successfully!")
    except FileExistsError:
      print("Directory already exists!")
    except OSError as e:
      print(f"Error creating directory: {e}")

def bmc_main(src, dest):
    bmc = importlib.import_module("bmc-tools.bmc-tools")
    count = -1
    verbose = False
    old = False
    bitmap = True
    width = 64
    # taken from main of bmc-tools
    bmcc = bmc.BMCContainer(verbose=verbose, count=count, old=old, big=bitmap, width=width)
    src_files = []
    if not os.path.isdir(dest):
      print("[!] Destination folder '%s' does not exist.%s" % (dest, os.linesep))
      exit(-1)
    elif os.path.isdir(src):
      print("[+++] Processing a directory...%s" % (os.linesep))
      for root, dirs, files in os.walk(src):
        for f in files:
          if f.rsplit(".", 1)[-1].upper() in ["BIN", "BMC"]:
            if verbose:
              print("[---] File '%s' has been found.%s" % (os.path.join(root, f), os.linesep))
            src_files.append(os.path.join(root, f))
      if len(src_files) == 0:
        print("[!] No suitable files were found under '%s' directory.%s" % (src, os.linesep))
        exit(-1)
    elif not os.path.isfile(src):
      print("[!] Invalid -s/--src parameter; use -h/--help for help.%s" % (os.linesep))
      exit(-1)
    else:
      print("[+++] Processing a single file: '%s'.%s" % (src, os.linesep))
      src_files.append(src)
    for src in src_files:
      if bmcc.b_import(src):
        bmcc.b_process()
        bmcc.b_export(dest)
        bmcc.b_flush()
    del bmcc

def run_bmc(src, dst):
    user = re.search(r'Users[\\/]([^\\/]+)', src)
    if user:
        user_folder = f'{user.group(1)}_rdp-bitmap'
        out_path = os.path.join(dst, user_folder)
        mkdir(out_path)
        bmc_main(src, out_path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out_path') # outfolder
    parser.add_argument('bitmap_path', action='store', type=str, nargs='+') # outfolder
    args = parser.parse_args()
    bitmap_path = " ".join(args.bitmap_path)
    print(bitmap_path)

    # {tool_path}/bmc-tools/bmc-tools.py -s {input} -d {outfolder} -b
    for path in glob.glob(bitmap_path):
      run_bmc(path, args.out_path)


if __name__ == '__main__':
  main()
