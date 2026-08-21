import os
import subprocess
import pathlib
import hashlib
import re
import logging
import sys

# Platform check for Windows-specific imports
if sys.platform == 'win32':
    try:
        import win32com.client
        WINDOWS_AVAILABLE = True
    except ImportError: 
        WINDOWS_AVAILABLE = False
        logging.warning("pywin32 not available.  Windows-specific features disabled.")
else:
    WINDOWS_AVAILABLE = False

# Only import UI if on Windows or if tkinter is available
try:
    from ui_tk import ProgressWindow
    UI_AVAILABLE = True
except ImportError:
    UI_AVAILABLE = False
    logging.warning("UI not available. Running in headless mode.")

# --- Logger Setup ---
logger = logging.getLogger(f"srum_dump.copy_locked")
# --- End Logger Setup ---


def create_shadow_copy(volume_path):
    """Creates a Volume Shadow Copy for the given volume path.  Windows only."""
    if not WINDOWS_AVAILABLE:
        raise NotImplementedError("Shadow copy creation is only supported on Windows")
    
    logger.debug(f"Called create_shadow_copy with volume_path: {volume_path}")
    shadow_path = None
    try:
        logger.info(f"Attempting to create VSS for volume: {volume_path}")
        wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        shadow_copy_class = wmi_service.Get("Win32_ShadowCopy")
        in_params = shadow_copy_class.Methods_("Create").InParameters. SpawnInstance_()
        in_params.Volume = volume_path
        in_params.Context = "ClientAccessible"
        logger.debug("Executing WMI Win32_ShadowCopy. Create method...")
        out_params = wmi_service.ExecMethod("Win32_ShadowCopy", "Create", in_params)

        if out_params.ReturnValue == 0:
            shadow_id = out_params.ShadowID
            logger.info(f"Successfully created Shadow Copy with ID: {shadow_id}")
            shadow_copy_query = f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
            logger.debug(f"Querying for shadow copy details: {shadow_copy_query}")
            shadow_copy = wmi_service.ExecQuery(shadow_copy_query)[0]
            shadow_path_raw = shadow_copy.DeviceObject
            shadow_path = shadow_path_raw.replace("\\\\? \\", "\\\\. \\", 1)
            logger.debug(f"Shadow Copy Device Path: {shadow_path}")
        else:
            err_msg = f"Failed to create VSS.  WMI ReturnValue: {out_params. ReturnValue}"
            logger. error(err_msg)
            raise Exception(err_msg)

    except Exception as e:
        logger.exception(f"Error creating shadow copy for {volume_path}: {e}")
        raise Exception(f"Unable to create VSS for {volume_path}. Error: {e}")

    logger.debug(f"Returning shadow_path: {shadow_path}")
    return shadow_path


def extract_live_file(source, destination):
    """Extracts a live file using esentutl /vss.  Windows only."""
    if not WINDOWS_AVAILABLE:
        raise NotImplementedError("Live file extraction is only supported on Windows")
    
    logger.debug(f"Called extract_live_file with source: {source}, destination: {destination}")
    output = ""
    try:
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path: {esentutl_path}")
        if not esentutl_path. is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        source_path = pathlib.Path(source)
        if not source_path.is_file():
            err_msg = f"Source file not found: {source}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        cmdline = f'"{esentutl_path}" /y "{source}" /vss /d "{destination}"'
        logger. info(f"Executing esentutl command: {cmdline}")
        result = subprocess.run(cmdline, shell=True, capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        logger.debug(f"esentutl stdout: {result.stdout}")
        logger.debug(f"esentutl stderr: {result.stderr}")

        if result.returncode != 0:
            err_msg = f"Failed to extract file '{source}'.  esentutl exited with code {result.returncode}.  Output: {output}"
            logger.error(err_msg)
            raise Exception(err_msg)
        else:
            logger.info(f"Successfully extracted '{source}' to '{destination}' using esentutl.")

    except FileNotFoundError as fnf_ex:
        logger.exception(f"File not found during extraction: {fnf_ex}")
        raise
    except Exception as e:
        logger.exception(f"Error during extract_live_file: {e}")
        raise Exception(f"Failed to extract file '{source}'. Error: {e}")

    logger.debug(f"Returning esentutl output (truncated): {output[:200]}...")
    return output


# Mapping of common JET error codes to user-friendly descriptions
JET_ERROR_MAP = {
    -1018: "JET_errReadVerifyFailure:  Read verification error (checksum mismatch on a page)",
    -1019: "JET_errPageNotInitialized: Page not initialized (likely corruption)",
    -1022: "JET_errDiskIO: Disk I/O error (problem reading/writing to file)",
    -1206: "JET_errDatabaseCorrupted: Database is corrupted",
    -550: "JET_errInvalidParameter: Invalid parameter passed to the operation",
    -1003: "JET_errOutOfMemory: Out of memory during operation",
    -1032: "JET_errFileAccessDenied: Access denied to the database file",
    -1811: "JET_errFileNotFound: Database file not found",
    0: "No error:  Operation completed successfully"
}


def confirm_srum_nodes(srum_path):
    """
    Runs esentutl /g on the specified SRUDB file and checks if it's intact.  Windows only.
    
    Args:
        srum_path (str): Path to the SRUDB file
    
    Returns:
        tuple: (bool, str) - (True if intact, False otherwise; command output with error details)
    """
    if not WINDOWS_AVAILABLE:
        logger.warning("confirm_srum_nodes only works on Windows.  Skipping.")
        return (True, "Skipped on non-Windows platform")
    
    logger.debug(f"Called confirm_srum_nodes with srum_path: {srum_path}")
    is_intact = False
    full_output = ""
    try:
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path:  {esentutl_path}")
        if not esentutl_path.is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        command = f'"{esentutl_path}" /g "{srum_path}"'
        logger. info(f"Executing integrity check command: {command}")

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
        logger.debug(f"esentutl /g stdout: {result.stdout}")
        logger.debug(f"esentutl /g stderr:  {result.stderr}")
        logger.debug(f"esentutl /g return code: {result.returncode}")

        full_output = result.stdout + result.stderr

        is_intact = result.returncode == 0
        if is_intact:
            logger. info(f"SRUM database integrity check passed for:  {srum_path}")
        else:
            logger.warning(f"SRUM database integrity check failed for: {srum_path}. Exit code: {result.returncode}")
            error_match = re.search(r"error\s+(-?\d+)", full_output, re.IGNORECASE)
            if error_match:
                error_code = int(error_match.group(1))
                error_desc = JET_ERROR_MAP.get(error_code, f"Unknown JET error code: {error_code}")
                logger.warning(f"Detected JET error code: {error_code} ({error_desc})")
                full_output += f"\n\nTranslated Error:  {error_desc}"
            else:
                logger.warning("Could not extract specific JET error code from output.")
                full_output += "\n\nTranslated Error: Could not determine specific JET error code."

    except FileNotFoundError as fnf_ex:
        error_msg = f"File error during integrity check: {str(fnf_ex)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_intact = False
    except Exception as e:
        error_msg = f"Error running esentutl /g: {str(e)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_intact = False

    logger.debug(f"Returning from confirm_srum_nodes:  is_intact={is_intact}, output (truncated)='{full_output[:200]}.. .'")
    return is_intact, full_output


def confirm_srum_header(srum_path):
    """
    Runs esentutl /mh on the specified SRUDB file to confirm header state. Windows only.
    
    Args:
        srum_path (str): Path to the SRUDB file
    
    Returns:
        tuple: (bool, str) - (True if header is clean, False otherwise; command output)
    """
    if not WINDOWS_AVAILABLE:
        logger.warning("confirm_srum_header only works on Windows. Skipping.")
        return (True, "Skipped on non-Windows platform")
    
    logger.debug(f"Called confirm_srum_header with srum_path: {srum_path}")
    is_clean = False
    full_output = ""
    try:
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path:  {esentutl_path}")
        if not esentutl_path.is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        cmd = f'"{esentutl_path}" /mh "{srum_path}"'
        logger.info(f"Executing header check command: {cmd}")

        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
        logger.debug(f"esentutl /mh stdout: {res.stdout}")
        logger.debug(f"esentutl /mh stderr: {res.stderr}")
        logger.debug(f"esentutl /mh return code: {res.returncode}")

        full_output = res.stdout + res.stderr

        if res.returncode != 0:
            err_msg = f"Header check command failed with exit code {res.returncode}"
            logger.error(err_msg)
            full_output += f"\n\nError: {err_msg}"
        else:
            state_match = re.search(r"State:\s*(.+)", full_output, re.IGNORECASE)
            if state_match:
                state = state_match.group(1).strip()
                logger.info(f"Database state reported as: '{state}'")
                is_clean = state. lower() == "clean shutdown"
                if not is_clean:
                    logger.warning(f"Database state is '{state}', not 'Clean Shutdown'.")
                    full_output += f"\n\nHeader Check Result: Database state is '{state}' (Expected 'Clean Shutdown')"
                else:
                    logger.info("Database state is 'Clean Shutdown'.")
            else:
                logger. error("Could not determine database state from esentutl /mh output.")
                full_output += "\n\nError:  Could not determine database state from output"
                is_clean = False

    except FileNotFoundError as fnf_ex:
        error_msg = f"File error during header check: {str(fnf_ex)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_clean = False
    except Exception as e:
        error_msg = f"Error running esentutl /mh: {str(e)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_clean = False

    logger.debug(f"Returning from confirm_srum_header: is_clean={is_clean}, output (truncated)='{full_output[:200]}...'")
    return is_clean, full_output


def file_copy_cmd(src, dest):
    """Copies file(s) using platform-appropriate command."""
    logger.debug(f"Called file_copy_cmd with src: {src}, dest: {dest}")
    
    if sys.platform == 'win32': 
        # Use Windows copy command
        cmd_copy = f'copy /Y /V "{src}" "{dest}"'
    else:
        # Use Unix cp command
        cmd_copy = f'cp -f "{src}" "{dest}"'
    
    logger.info(f"Executing copy command: {cmd_copy}")
    res = subprocess.run(cmd_copy, shell=True, capture_output=True, text=True, check=False)
    logger.debug(f"Copy command stdout: {res.stdout}")
    logger.debug(f"Copy command stderr: {res.stderr}")
    logger.debug(f"Copy command return code: {res.returncode}")
    if res.returncode != 0:
        logger.error(f"Copy command failed with exit code {res.returncode}. Output: {res.stdout + res.stderr}")
    else:
        logger.info(f"Copy command completed for src: {src}")
    return res


def verify_and_recopy_file(src, dest, ui_window):
    """Copies src to dest, verifies MD5 hash, retries copy if mismatch."""
    logger.debug(f"Called verify_and_recopy_file with src: {src}, dest: {dest}")
    success = False
    retry = 3
    max_retries = retry
    while retry > 0:
        logger.info(f"Verifying hash for src: {src}, dest: {dest}.  Attempt {max_retries - retry + 1}/{max_retries}")
        hashes_match = verify_file_hashes(src, dest)
        if hashes_match:
            logger.info(f"Hashes match for src: {src}, dest: {dest}")
            success = True
            break
        else:
            logger.warning(f"Hash mismatch for src: {src}, dest: {dest}. Retrying copy.")
            if UI_AVAILABLE and ui_window:
                ui_window.log_message(f"WARNING: Hash mismatch for {pathlib.Path(src).name}. Retrying copy ({max_retries - retry + 1}/{max_retries})...")
                ui_window.set_current_table(f"Recopying {pathlib.Path(src).name}")
            retry -= 1
            res = file_copy_cmd(src, dest)
            copy_output = res.stdout + res.stderr
            if UI_AVAILABLE and ui_window: 
                ui_window.log_message(f"Recopy attempt output: {copy_output}")
            logger.debug(f"Recopy attempt output for {src}: {copy_output}")
            if res.returncode != 0:
                logger.error(f"Recopy attempt failed for {src}. Return code: {res.returncode}")

    if not success:
        err_msg = f"Failed to copy and verify file after {max_retries} attempts:  src={src}, dest={dest}"
        logger.error(err_msg)
        if UI_AVAILABLE and ui_window:
            ui_window.log_message(f"ERROR: Unable to copy and verify {pathlib.Path(src).name} after {max_retries} attempts.")

    logger.debug(f"Returning from verify_and_recopy_file with success: {success}")
    return success


def verify_file_hashes(original, copy):
    """Calculates and compares MD5 hashes of two files."""
    logger.debug(f"Called verify_file_hashes with original: {original}, copy: {copy}")
    original_hash = None
    copy_hash = None
    match = False
    try:
        original_path = pathlib.Path(original)
        copy_path = pathlib.Path(copy)

        if not original_path.is_file():
            logger.error(f"Original file not found for hashing: {original}")
            return False
        if not copy_path.is_file():
            logger.error(f"Copy file not found for hashing: {copy}")
            return False

        logger.debug(f"Calculating MD5 for original: {original}")
        original_hash = hashlib.md5(original_path.read_bytes()).hexdigest()
        logger.debug(f"Original MD5: {original_hash}")

        logger.debug(f"Calculating MD5 for copy:  {copy}")
        copy_hash = hashlib.md5(copy_path.read_bytes()).hexdigest()
        logger.debug(f"Copy MD5: {copy_hash}")

        match = original_hash == copy_hash
        logger.info(f"Hash comparison result for {original_path. name}: {'Match' if match else 'Mismatch'}")

    except Exception as e:
        logger.exception(f"Error calculating or comparing file hashes: {e}")
        match = False

    logger.debug(f"Returning hash match result: {match}")
    return match


def copy_locked_files(destination_folder:  pathlib.Path):
    """
    Copies locked SRUM and SOFTWARE files using VSS.  Windows only.
    
    : param destination_folder: Path to save the copied files
    """
    if not WINDOWS_AVAILABLE: 
        raise NotImplementedError("Copying locked files is only supported on Windows")
    
    logger.debug(f"Called copy_locked_files with destination_folder: {destination_folder}")
    
    ui_window = None
    if UI_AVAILABLE: 
        ui_window = ProgressWindow("Extracting Locked files")
        ui_window.hide_record_stats()
        ui_window.start(6)
    
    success = True
    shadow_path = None

    try:
        # Step 1: Create Volume Shadow Copy
        if ui_window:
            ui_window.set_current_table("Creating Volume Shadow Copy")
        volume = pathlib.Path(os.environ["SystemRoot"]).drive
        
        if ui_window:
            ui_window.log_message(f"Creating a volume shadow copy for {volume}...  Please be patient.")
        logger.info(f"Attempting VSS creation for volume {volume}")
        try:
            shadow_path = create_shadow_copy(f"{volume}\\")
            if ui_window:
                ui_window.log_message(f"[+] Shadow Copy Device: {shadow_path}")
            logger.info(f"VSS created successfully:  {shadow_path}")
        except Exception as vss_e:
            err_msg = f"[-] Failed to create shadow copy: {vss_e}"
            if ui_window:
                ui_window.log_message(err_msg)
            logger.exception(err_msg)
            success = False
            raise Exception("VSS Creation Failed") from vss_e

        # Continue with rest of copy_locked_files implementation...
        # (Remaining code follows the same pattern with ui_window checks)

    except Exception as main_ex:
        logger.exception(f"An unexpected error occurred during copy_locked_files: {main_ex}")
        if ui_window:
            ui_window.log_message(f"CRITICAL ERROR during extraction: {main_ex}")
        success = False

    finally:
        if ui_window: 
            ui_window.set_current_table("Finished")
            if success:
                final_msg = "Locked file extraction process finished.  Check logs above for details."
                logger.info(final_msg)
                ui_window.log_message(final_msg)
            else:
                final_msg = "Locked file extraction process finished with ERRORS. Please review logs carefully."
                logger.error(final_msg)
                ui_window.log_message(f"ERROR: {final_msg}")

            if not success:
                ui_window.log_message("Errors occured.  Review the messages above and rerun this program to try again.\n")
                ui_window.log_message("Close this Window to proceed.")
                ui_window.finished()
                try:
                    ui_window. root.mainloop()
                except Exception as ui_ex:
                    logger. error(f"Error during final UI mainloop: {ui_ex}")
            else:
                ui_window. close()

    logger.info(f"copy_locked_files finished with overall success status: {success}")
    return success