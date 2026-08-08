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

def resolve_sbecmd(tool_path: Path) -> list:
    """Build the command prefix for SBECmd on this platform.

    Windows uses the native SBECmd.exe; Linux uses the bundled dotnet runtime
    against SBECmd.dll, falling back to dotnet on PATH.
    """
    net_dir = tool_path / 'Get-ZimmermanTools' / 'net9'
    sbecmd_exe = net_dir / 'SBECmd.exe'
    sbecmd_dll = net_dir / 'SBECmd.dll'

    if os.name == 'nt' and sbecmd_exe.is_file():
        return [str(sbecmd_exe)]

    bundled_dotnet = tool_path / '.dotnet' / ('dotnet.exe' if os.name == 'nt' else 'dotnet')
    dotnet = str(bundled_dotnet) if bundled_dotnet.is_file() else shutil.which('dotnet')
    if dotnet and sbecmd_dll.is_file():
        return [dotnet, str(sbecmd_dll)]

    return None

def process_hive(sbecmd_cmd: list, hive_path: Path, output_dir: Path, final_filename: str, username: str):
    final_path = output_dir / final_filename

    # Use context managers to guarantee cleanup even if the script crashes
    with tempfile.TemporaryDirectory() as stage_dir, tempfile.TemporaryDirectory() as temp_out_dir:
        
        try:
            # 1. Copy hive and transaction logs (case-insensitive match), skipping
            # collection artifacts such as the .idx files UAC/KAPE leave alongside hives
            hive_name_lower = hive_path.name.lower()
            for file in hive_path.parent.iterdir():
                name = file.name.lower()
                if not name.startswith(hive_name_lower):
                    continue
                suffix = name[len(hive_name_lower):]
                if suffix and not suffix.startswith('.log'):
                    continue
                shutil.copy2(file, stage_dir)

            # 2. Execute SBECmd pointing output to isolated temp_out_dir
            cmd = sbecmd_cmd +[
                '-d', stage_dir,
                '--csv', temp_out_dir,
                '--csvf', final_filename
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # 3. Locate the single generated CSV (bypassing SBECmd's prefix logic)
            generated_files = list(Path(temp_out_dir).glob("*.csv"))
            if not generated_files:
                detail = (proc.stderr or proc.stdout or '').strip().splitlines()
                logging.warning(
                    f"No shellbags output for {username} ({hive_path.name}), "
                    f"exit code {proc.returncode}: {detail[-1] if detail else 'no output'}"
                )
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
            else:
                logging.info(f"No shellbag entries found for {username} ({hive_path.name})")

        except Exception as e:
            logging.error(f"Error processing {username} ({hive_path.name}): {e}")

def main():
    setup_logging()
    
    parser = argparse.ArgumentParser(description="Automated ShellBags parser with accurate user attribution.")
    parser.add_argument("--users", required=True, type=Path, help="Path to Users directory")
    parser.add_argument("--tool", "--tool_path", dest="tool_path", required=True, type=Path,
                        help="Base path for ZimmermanTools")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()

    sbecmd_cmd = resolve_sbecmd(args.tool_path)
    if sbecmd_cmd is None:
        logging.error(
            f"Unable to locate SBECmd. Expected SBECmd.exe/SBECmd.dll under "
            f"{args.tool_path / 'Get-ZimmermanTools' / 'net9'} plus a dotnet runtime for the .dll"
        )
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
            process_hive(sbecmd_cmd, ntuser, args.out, f"{username}_NTUSER.csv", username)

        # Process UsrClass.dat
        usrclass = get_path_insensitive(profile,["AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"])
        if usrclass and usrclass.is_file():
            process_hive(sbecmd_cmd, usrclass, args.out, f"{username}_UsrClass.csv", username)

    logging.info("Extraction complete.")

if __name__ == "__main__":
    main()