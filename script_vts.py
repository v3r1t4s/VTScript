"""import of modules"""

import argparse
import os
import sys
from pathlib import Path
import json
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
                return
        else:
            print("[-] The path is not valid!")
            return
    except ValueError as val_err:
        exception_handler(True, val_err)
        return

    return res


def read_api_key(file):
    """Read API Key from the file path provided in get_path()"""

    try:
        with open(file, "r", encoding="UTF-8") as api_file:
            return api_file.readline()
    except IOError as io_err:
        exception_handler(True, io_err)
        return


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
        return


def parse_json(res, string):
    """Parse json response from VT to find malicious signs"""
    # Print the line to separate each parsing when having multiple responses...
    print("\n-------------------------------------------------------------------------------------")

    # Printing out the string that's being parsed at this time
    print(f"\n[*] Checking {string}")

    # Loading the output into a dictionnary
    res_dic = json.loads(res)

    # Check if VT returns us something interesting when we query api_req(), If not, return.
    if res_dic['data'] == []:
        print("[-] Sorry but VirusTotal didn't found something...")
        return

    # text is a unique key (in the dictionnary)
    # only found in the response of a Tag comment specific API query
    # If we're finding this key return to main
    if "text" in res_dic['data'][0]['attributes']:
        print("[*] Sorry but searching Tag Comment isn't available.")
        print(
            "[*] If you want to search one go there: https://www.virustotal.com/gui/home/search")
        return

    # Parsing the output for last analysis statistics
    analysis_stat = res_dic['data'][0]['attributes']['last_analysis_stats']

    print(
        f"[*] Latest Analysis Statistics available counting the number of reports: {analysis_stat}")

    # Checking if malicious key has a hit
    if analysis_stat['malicious']:
        print(
            "[*] Detailed reports about this IOC (engine name : result of the analysis):")

        # Preparing to parse the output for latest analysis results
        analysis_res = res_dic['data'][0]['attributes']['last_analysis_results']

        # Parsing the output and checking every analysis made to find malicious one
        for value in analysis_res.values():
            if "malicious" in value['category']:
                print(f"[+] {value['engine_name']} : {value['result']}")
    else:
        print("[+] This doesn't seems to be an IOC.")

    return


if __name__ == '__main__':

    # Create the parser to have arguments in the script
    parser = argparse.ArgumentParser()

    # Adding string argument
    parser.add_argument('--string', type=str, )

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
    # Remove any blank line so we can send proper string to the api_req()
    if args.file:
        FILE_ARG = True

        # Checking if the file is well formatted (no blank line, a string on each line),
        # if not format the file
        try:
            with open(sys.argv[2], 'r+', encoding="UTF-8") as f:
                lines = f.readlines()
                f.seek(0)
                f.writelines(line for line in lines if line.strip())
                f.truncate()
        except IOError as strip_err:
            exception_handler(True, strip_err)
            exit(1)

    STRING = ""

    # Call the get_path function to have the path of the API Key File
    path = get_path(STRING)

    # If we receive nothing quit with error
    if path is None:
        exit(1)

    # Call the read_api_key function to read the API Key from the file
    api_key = read_api_key(path)

    # If we receive nothing quit with error
    if api_key is None:
        exit(1)

    RESPONSE = ""

    # If user launched the script with the file cmdline arg
    # else then string cmdline argument scenario start
    if FILE_ARG:
        # Create a list with each elements on each line
        data_list = args.file.readlines()

        # Initialize request var to check how many request we sent
        REQUEST = 0

        # Using for loop to sent each element of the list to the api request function
        for d in data_list:
            RESPONSE = api_req(api_key, d)

            # If we receive nothing quit with error
            if RESPONSE is None:
                exit(1)

            parse_json(RESPONSE, d)

            REQUEST += 1

            if REQUEST == 4:
                print("\n[*] Sorry but the quota is 4 lookups/min")
                exit(0)
    else:
        RESPONSE = api_req(api_key, args.string)

        # If we receive nothing quit with error
        if RESPONSE is None:
            exit(1)

        # If we receive nothing quit with error
        if parse_json(RESPONSE, args.string) is None:
            exit(1)
        else:
            exit(0)
