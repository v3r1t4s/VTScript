"""import of modules"""
import Helpers
from pathlib import Path


def get_user_input_and_parse_filename(exclusion, excluded_character):
    """Function used to get a filename as input and parse it until we got a proper one"""
    filename_parsed = ""
    while filename_parsed.isalnum() is False:
        try:
            filename = input(
                "Please provide a filename for your report (without an extension / _ is accepted between chars): ")
            filename_parsed = filename
            if exclusion is True:
                if filename != '':
                    if filename[0] != excluded_character and filename[-1] != excluded_character and (excluded_character * 2 in filename) is not True:
                        filename_parsed = filename.replace(excluded_character, '')
        except ValueError as val_err:
            Helpers.exception_handler(True, val_err)
            return None
    filename = Path(filename + ".txt")
    if filename.is_file():
        choice = ""
        while choice not in ["overwrite", "change"]:
            choice = input("[-] This file already exists on the system, do you want to overwrite or change the filename (overwrite/change): ")
        if choice == "overwrite":
            return filename
        else:
            return None
    else:
        return filename


def WinOutputMain(interesting_event_list):
    """Function used as main for the WinOutput module"""
    filename_to_create = None
    while filename_to_create is None:
        filename_to_create = get_user_input_and_parse_filename(True, '_')
    data_to_append = ""
    if interesting_event_list == []:
        data_to_append = "[+] Your system seems clean! The analysis engine didn't return any events!"
    else:
        for i in interesting_event_list:
            data_to_append += str(i) + "\n"
    print(f"[*] Writing a report named {filename_to_create} in {Path.cwd()}...")
    try:
        with open(filename_to_create, "w", encoding="UTF-8") as file:
            file.write(data_to_append + "\n")
            print("[+] You report is done!")
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
        print("[-] We couldn't write you a report.")
        exit(1)
