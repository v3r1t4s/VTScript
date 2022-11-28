"""import of modules"""
import os
import sys
from pathlib import Path


def read_api_key(file):
    """Read API Key from the file path provided in get_path()"""
    try:
        with open(file, "r", encoding="UTF-8") as api_file:
            return api_file.readline()
    except IOError as io_err:
        exception_handler(True, io_err)
    return None


def check_if_filepath_exists(raw_path):
    """Function use to check if path and file exist"""
    if os.path.exists(raw_path):
        print("[+] The path is valid!")
        parsed_path = Path(raw_path)
        if parsed_path.is_file():
            print("[+] We did find the file!")
            return parsed_path
        else:
            print("[-] We didn't found the file!")
            return None
    else:
        print("[-] The path of the File is not valid!")
        return None


def exception_handler(print_exception=False, exception=""):
    """This function enhances default Python Error handling
    It will print the line in code that the error occurred on"""
    if print_exception is True:
        print(exception)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        del exc_type, exc_obj
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("Exception on line: ", exc_tb.tb_lineno, " in ", fname)
    return None
