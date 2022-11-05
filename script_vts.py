"""import of modules"""

import argparse
import os
import sys
from pathlib import Path
import requests


def exception_handler(print_exception=False, exception=""):
    """This function enhances default Python Error handling
    It will print the line in code that the error occurred on"""
    if print_exception is True:
        print(exception)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        del exc_type, exc_obj
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("Exception on line: ", exc_tb.tb_lineno, " in ", fname)
    return

# Might recode or put a helper function just before to list path when hitting tab...


def get_path(prompt):
    """Get Path with input(), check if both path/file exist"""

    try:
        res = input("Please input an absolute path: " + prompt)
        if os.path.exists(res):
            print("[+] The path is valid!")
            res = Path(res)

            if res.is_file():
                print("[+] We did find the file!")
            else:
                print("[-] We didn't found the file!")
                exit(1)
        else:
            print("[-] The path is not valid!")
            exit(1)
    except ValueError as err:
        exception_handler(True, err)
        exit(1)

    return res


def read_api_key(file):
    """Read API Key from the file path provided in get_path()"""

    try:
        with open(file, "r", encoding="UTF-8") as api_file:
            return api_file.readline()
    except IOError as err:
        exception_handler(True, err)
        exit(1)


def api_req(key, data):
    """Function to make api request to search for a string"""
    url = f"https://www.virustotal.com/api/v3/search?query={data}"

    headers = {"accept": "application/json",
               "x-apikey": key
               }

    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.text
    else:
        print(f"[-] HTTP response wasn't successful: {response.status_code}")
        exit(1)


if __name__ == '__main__':

    # Create the parser to have arguments in the script
    parser = argparse.ArgumentParser()

    # Adding string argument
    parser.add_argument('--string', type=str, )  # required=True)

    # Adding File argument
    parser.add_argument('--file', type=argparse.FileType('r'))

    # Parse the argument
    args = parser.parse_args()

    # Check if an argument is provided
    if len(sys.argv) <= 1:
        print("[-] Please provide at least one command line argument")
        exit(1)

    # Set file argument to false until we know there's one
    FILE_ARG = False

    # Set to true if we find that it is used as cmdline argument
    if args.file:
        FILE_ARG = True

    STRING = ""

    # Call the get_path function to have the path of the API Key File
    path = get_path(STRING)

    # Call the read_api_key function to read the API Key from the file
    api_key = read_api_key(path)

    RESPONSE = ""

    # If user launched the script with the file cmdline arg
    # else then string cmdline argument scenario start
    if FILE_ARG:
        # Create a list with each elements on each line
        data_list = args.file.readlines()

        # Initialize Lookup var to check how many request we sent
        LOOKUP = 0

        # Using for loop to sent each element of the list to the api request function
        for d in data_list:
            RESPONSE = api_req(api_key, d)
            print(RESPONSE)
            LOOKUP += 1
            if LOOKUP == 4:
                print("[*] Sorry but the quota is 4 lookups/min")
                exit(0)
    else:
        RESPONSE = api_req(api_key, args.string)
        print(RESPONSE)
