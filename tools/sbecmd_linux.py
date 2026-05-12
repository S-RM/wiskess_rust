#!/usr/bin/env python3
import os
import shutil
import argparse
import subprocess
import tempfile
import logging
import polars as pl
from pathlib import Path

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def get_path_insensitive(base_path: Path, segments: list) -> Path:
    current = base_path
    for part in segments:
        found = False
        if current.is_dir():
            try:
                for child in current.iterdir():
                    if child.name.lower() == part.lower():
                        current = child
                        found = True
                        break
            except PermissionError:
                return None
        if not found:
            return None
    return current

def process_hive(dotnet: Path, tool: Path, hive_path: Path, output_dir: Path, final_filename: str, username: str):
    final_path = output_dir / final_filename

    # Use context managers to guarantee cleanup even if the script crashes
    with tempfile.TemporaryDirectory() as stage_dir, tempfile.TemporaryDirectory() as temp_out_dir:
        
        try:
            # 1. Copy hive and transaction logs (case-insensitive match)
            hive_name_lower = hive_path.name.lower()
            for file in hive_path.parent.iterdir():
                if file.name.lower().startswith(hive_name_lower):
                    shutil.copy2(file, stage_dir)

            # 2. Execute SBECmd pointing output to isolated temp_out_dir
            cmd =[
                str(dotnet),
                str(tool),
                '-d', stage_dir,
                '--csv', temp_out_dir,
                '--csvf', final_filename
            ]
            subprocess.run(cmd, capture_output=True, check=False)

            # 3. Locate the single generated CSV (bypassing SBECmd's prefix logic)
            generated_files = list(Path(temp_out_dir).glob("*.csv"))
            if not generated_files:
                return

            actual_output = generated_files[0]

            # 4. Inject Username and save to final destination
            df = pl.read_csv(actual_output, ignore_errors=True, infer_schema_length=10000)
            
            if not df.is_empty() and len(df.columns) > 0:
                df = df.with_columns(pl.lit(username).alias("Username"))
                
                # Reorder columns to ensure Username is first
                cols = ['Username'] +[col for col in df.columns if col != 'Username']
                df = df.select(cols)
                
                df.write_csv(final_path)
                logging.info(f"Processed successfully: {final_filename}")

        except Exception as e:
            logging.error(f"Error processing {username} ({hive_path.name}): {e}")

def main():
    setup_logging()
    
    parser = argparse.ArgumentParser(description="Automated ShellBags parser with accurate user attribution.")
    parser.add_argument("--users", required=True, type=Path, help="Path to Users directory")
    parser.add_argument("--tool_path", required=True, type=Path, help="Base path for ZimmermanTools")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()

    dotnet_path = args.tool_path / '.dotnet' / 'dotnet'
    sbecmd_path = args.tool_path / 'Get-ZimmermanTools' / 'net9' / 'SBECmd.dll'

    # Pre-flight checks
    if not dotnet_path.exists() or not sbecmd_path.exists():
        logging.error(f"Missing executables. Ensure dotnet and SBECmd.dll exist at {args.tool_path}")
        return

    if not args.out.exists():
        args.out.mkdir(parents=True)

    logging.info(f"Initiating ShellBags extraction across: {args.users}")

    for profile in args.users.iterdir():
        if not profile.is_dir():
            continue

        username = profile.name
        if username.lower() in['default', 'default user', 'public', 'all users']:
            continue

        # Process NTUSER.DAT
        ntuser = get_path_insensitive(profile, ["NTUSER.DAT"])
        if ntuser and ntuser.is_file():
            process_hive(dotnet_path, sbecmd_path, ntuser, args.out, f"{username}_NTUSER.csv", username)

        # Process UsrClass.dat
        usrclass = get_path_insensitive(profile,["AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"])
        if usrclass and usrclass.is_file():
            process_hive(dotnet_path, sbecmd_path, usrclass, args.out, f"{username}_UsrClass.csv", username)

    logging.info("Extraction complete.")

if __name__ == "__main__":
    main()