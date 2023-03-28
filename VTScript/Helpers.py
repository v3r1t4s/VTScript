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

def verify_at_least_x_command_line_arguments(arguments, argument_count):
    """Function checking the number of arguments"""
    if len(arguments) > argument_count:
        return arguments
    return None


def opening_file_stripping_new_lines(file):
    """ Checking if the file is well formatted (no blank line, a string on each line), if not format the file"""
    try:
        with open(file, encoding="UTF-8") as in_file, open(file, 'r+', encoding="UTF-8") as out_file:
            out_file.writelines(line for line in in_file if line.strip())
            out_file.truncate()
    except IOError as strip_err:
        exception_handler(True, strip_err)
        exit(1)
    return None


def get_path_from_user(text_for_input):
    """Get Path with input(), check if both path/file exist"""
    try:
        prompt = input(text_for_input)
        if check_if_filepath_exists(prompt) is None:
            exit(1)
    except ValueError as val_err:
        exception_handler(True, val_err)
        return None
    return prompt


def counting_lines_of_file(filename_to_count_to):
    """Function used to count number of lines in a file"""
    try:
        with open(filename_to_count_to, "r", encoding="UTF-8") as file:
            nb_of_lines = len(file.readlines())
            return nb_of_lines
    except IOError as io_err:
        exception_handler(True, io_err)
    return None