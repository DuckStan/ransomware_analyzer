import subprocess
import os
import xml.etree.ElementTree as ET
import shutil
import time
import win32api
import win32con
import hashlib
import json


def get_strange_extensions(folder_path):

    extensions = set()
    for filename in os.listdir(folder_path):
        if os.path.isfile(os.path.join(folder_path, filename)) \
                and not filename.endswith(('.jpg', '.png')):
            extension = os.path.splitext(filename)[1].lower()
            extensions.add(extension)
    return list(extensions)


def calculate_folder_hashes(folder_path):

    file_hashes = []
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                file_hashes.append(file_hash)
    return file_hashes


def check_folder_integrity(folder_path, prev_hashes):

    new_hashes = calculate_folder_hashes(folder_path)

    if set(prev_hashes) == set(new_hashes):
        return "Integrity of the files is complete", 1
    elif set(prev_hashes).issubset(set(new_hashes)):
        return "Integrity is there, but new files were added", -1
    elif set(prev_hashes).isdisjoint(set(new_hashes)):
        return "Integrity is broken completely", 0
    else:
        return "Integrity is saved partially", 0.5


def find_txt_file(folder_path):

    for filename in os.listdir(folder_path):
        if filename.endswith('.txt') and os.path.isfile(os.path.join(folder_path, filename)):
            return filename
    return None


def copy_folder_contents(source_folder, destination_folder):
    # Get the absolute paths to the folders
    source_path = os.path.abspath(os.path.join(os.path.dirname(__file__), source_folder))
    destination_path = os.path.abspath(os.path.join(os.path.dirname(__file__), destination_folder))

    # Check if source folder exists
    if not os.path.exists(source_path):
        raise FileNotFoundError("Source folder does not exist")

    # Check if destination folder exists
    if not os.path.exists(destination_path):
        raise FileNotFoundError("Destination folder does not exist")

    # Copy the contents of the source folder to the destination folder
    for filename in os.listdir(source_path):
        source_file_path = os.path.join(source_path, filename)
        destination_file_path = os.path.join(destination_path, filename)
        try:
            if os.path.isfile(source_file_path):
                shutil.copy(source_file_path, destination_file_path)
            elif os.path.isdir(source_file_path):
                shutil.copytree(source_file_path, destination_file_path)
        except Exception as e:
            print(f"Error copying file {source_file_path}: {e}")


def copy_exe(src_path):
    # define script and dst_path location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dst_path = os.path.join(script_dir, "sandbox_folder", "interesting_file_folder", "interesting_file.exe")
    try:
        # Check if source file exists
        if not os.path.exists(src_path):
            raise FileNotFoundError("Source file does not exist")

        # Check if source file is an .exe file
        if not src_path.endswith(".exe"):
            raise ValueError("Source file is not an .exe file")

        # Check if destination folder exists
        if not os.path.exists(os.path.dirname(dst_path)):
            raise FileNotFoundError("Destination folder does not exist")

        # Copy the .exe file to the destination folder
        shutil.copy(src_path, dst_path)
        print("File copied successfully!")
    except Exception as e:
        print(f"Error: {str(e)}")


def clear_folder(relative_path):
    # Get the absolute path to the folder
    folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), relative_path))

    # Remove all files and subdirectories inside the folder
    for filename in os.listdir(folder_path):

        file_path = os.path.join(folder_path, filename)
        attributes = win32api.GetFileAttributes(file_path)

        # Check if the file is read-only
        if attributes & win32con.FILE_ATTRIBUTE_READONLY:
            print('File is currently set as read-only.')
            # Remove the read-only attribute
            win32api.SetFileAttributes(file_path, attributes & ~win32con.FILE_ATTRIBUTE_READONLY)

        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")


def create_config():
    # Define the path to the Windows Sandbox configuration file
    #config_file_path = os.path.dirname(os.path.abspath(__file__))r"C:\path\to\WindowsSandbox.wsb"

    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    #Get config file path
    config_file_path = os.path.join(script_dir, "configs", "WindowsSandbox.wsb")

    # Define the relative paths to the host folders
    tooling_path = os.path.join(script_dir, "sandbox_folder", "tooling")
    images_path = os.path.join(script_dir, "sandbox_folder", "images")
    interesting_file_folder_path = os.path.join(script_dir, "sandbox_folder", "interesting_file_folder")

    # Load the Windows Sandbox configuration file
    tree = ET.parse(config_file_path)
    root = tree.getroot()


    # Replace the host folder paths with relative paths
    for folder in root.iter("MappedFolder"):
        sandbox_folder = folder.find("SandboxFolder").text
        if sandbox_folder == r"c:\tooling":
            folder.find("HostFolder").text = tooling_path
        elif sandbox_folder == r"c:\images":
            folder.find("HostFolder").text = images_path
        elif sandbox_folder == r"c:\interesting_file_folder":
            folder.find("HostFolder").text = interesting_file_folder_path
    # Write the updated configuration file to disk
    tree.write(config_file_path)

    return config_file_path


def rewind_folders():

    script_dir = os.path.dirname(os.path.abspath(__file__))
    images_path = os.path.join(script_dir, "sandbox_folder", "images")
    interesting_file_folder_path = os.path.join(script_dir, "sandbox_folder", "interesting_file_folder")
    images_backup_path = os.path.join(script_dir, "sandbox_folder", "images_backup")

    clear_folder(images_path)
    clear_folder(interesting_file_folder_path)
    copy_folder_contents(images_backup_path, images_path)


def is_ransomware(file_path):

    #The json to be output (dicitionary in python)
    results = {}

    #Save the hash values
    script_dir = os.path.dirname(os.path.abspath(__file__))
    images_path = os.path.join(script_dir, "sandbox_folder", "images")
    images_hashes = calculate_folder_hashes(images_path)

    # Create Windows Sandbox config file (change the mapped folders)
    config_path = create_config()

    #Escape "\" to make it run in a shell >:(
    #config_path = config_path.replace("\", "\\")

    print(config_path)
    # Copy analyzed exe in a mapped folder
    copy_exe(file_path)

    #START SANDBOX
    command_start = ["powershell", config_path]
    #END SANDBOX
    command_end = ["powershell", "Get-Process -Name WindowsSandboxClient | Stop-Process -Force -ErrorAction SilentlyContinue"]
    command_parse = []
    try:
        # Run the Windows Sandbox using the WSB configuration file
        subprocess.run(command_start)
        print("Windows Sandbox started successfully!")
    except subprocess.CalledProcessError as e:
        print("Error running Windows Sandbox:", e)

    time.sleep(120)

    try:
        # Run the Windows Sandbox using the WSB configuration file
        subprocess.run(command_end)
        print("Windows Sandbox stopped successfully!")
    except subprocess.CalledProcessError as e:
        print("Error stopped Windows Sandbox:", e)
    # Execute the command within Windows Sandbox
    #subprocess.run(command)
    time.sleep(10)

    (results['integrity_status'], results['integrity_score']) = check_folder_integrity(images_path, images_hashes)
    results['ransom_note_filename'] = find_txt_file(images_path)
    results['strange_extensions'] = get_strange_extensions(images_path)

    results['score'] = 0
    if -1 < results['integrity_score'] < 1:
        results['score'] = 100
    elif results['ransom_note_filename']:
        results['score'] = 100
    elif results['strange_extensions']:
        results['score'] = 100
    else:
        results['score'] = 0


    #parse_logs()
    #time.sleep(10)
    rewind_folders()

    return results
