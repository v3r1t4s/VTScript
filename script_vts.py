"""import of modules"""

import os
import sys
import json
import argparse
import requests
from time import sleep
from pathlib import Path


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


def get_path(prompt):
    """Get Path with input(), check if both path/file exist"""

    try:
        prompt = input("Please input an absolute path: ")
        if os.path.exists(prompt):
            print("[+] The path is valid!")
            prompt = Path(prompt)

            if prompt.is_file():
                print("[+] We did find the file!")
            else:
                print("[-] We didn't found the file!")
                exit(1)
        else:
            print("[-] The path is not valid!")
            exit(1)
    except ValueError as val_err:
        exception_handler(True, val_err)
        return

    return prompt


def read_api_key(file):
    """Read API Key from the file path provided in get_path()"""

    try:
        with open(file, "r", encoding="UTF-8") as api_file:
            return api_file.readline()
    except IOError as io_err:
        exception_handler(True, io_err)
        return


def search_api_request(key, data):
    """Function to make api request to search for a string"""
    url = f"https://www.virustotal.com/api/v3/search?query={data}"

    headers = {"accept": "application/json",
               "x-apikey": key
               }

    response_search_api = requests.get(url, headers=headers, timeout=10)

    if response_search_api.status_code == 200:
        return response_search_api.text

    print(
        f"[-] HTTP response wasn't successful: {response_search_api.status_code}")
    return


def file_reputation_api_request(key, hash_file_reputation):
    """Function to make api request to get a file report"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_file_reputation}"

    headers = {"accept": "application/json",
               "x-apikey": key
               }

    response_file_reputation = requests.get(url, headers=headers, timeout=10)

    if response_file_reputation.status_code == 200:
        return response_file_reputation.text

    print(
        f"[-] HTTP response wasn't successful: {response_file_reputation.status_code}")
    return


def parse_json(res_parse_json, string_parse_json, file_reputation_parse_json):
    """Parse json response from VT to find malicious signs"""
    # Print the line to separate each parsing when having multiple responses...
    print("\n-------------------------------------------------------------------------------------")

    # Printing out the string that's being parsed at this time
    print(f"\n[*] Checking {string_parse_json}")

    # Removing \n character
    string_parse_json = string_parse_json.replace('\n', '')

    # Loading the output into a dictionnary
    res_dic = json.loads(res_parse_json)

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

    malicious = analysis_stat['malicious']

    # Checking if malicious key has a hit
    if malicious:
        print(
            "[*] Detailed reports about this IOC (engine name : result of the analysis):")

        # Preparing to parse the output for latest analysis results
        analysis_res = res_dic['data'][0]['attributes']['last_analysis_results']

        # Parsing the output and checking every analysis made to find malicious one
        for value in analysis_res.values():
            if "malicious" in value['category']:
                print(f"[+] {value['engine_name']} : {value['result']}")

    # Checking if string provided was a hash
    check_hash = '.' in string_parse_json

    if malicious >= 3 and check_hash is not True:
        print(f"\n[+] {string_parse_json} is definitely malicious")

        file_reputation_parse_json = True
        print(
            f"\n[*] Writing a file report, since the hash was flagged {malicious} times...")

        return file_reputation_parse_json
    elif malicious:
        print(f"\n[+] {string_parse_json} is definitely malicious")
    else:
        print("[+] This doesn't seems to be an IOC.")

    return


def write_file_reputation_report(key, string_file_reputation):
    """Function to write a file reputation report"""
    file_report = file_reputation_api_request(key, string_file_reputation)

    filename = ""
    filename_parsed = ""

    while filename_parsed.isalnum() is False:
        try:
            filename = input(
                "Please provide a filename (without an extension / _ is accepted between chars): ")

            filename_parsed = filename

            if filename[0] != '_' and filename[-1] != '_' and filename.count('_') == 1:
                filename_parsed = filename.replace('_', '')

        except ValueError as val_err:
            exception_handler(True, val_err)

    try:
        with open(f"{filename}.json", "w", encoding="UTF-8") as file:
            file.write(file_report)
    except IOError as io_err:
        exception_handler(True, io_err)
        return

    print(
        f"[+] The file report for {string_file_reputation} can be found as {filename}.json in {Path.cwd()}")

    return


def formating_file():
    """ Checking if the file is well formatted (no blank line, a string on each line),
    if not format the file"""
    try:
        with open(sys.argv[2], encoding="UTF-8") as in_file, open(sys.argv[2], 'r+', encoding="UTF-8") as out_file:
            out_file.writelines(line for line in in_file if line.strip())
            out_file.truncate()
    except IOError as strip_err:
        exception_handler(True, strip_err)
        exit(1)

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
    file_arg = False

    # Set to true if we find that it is used as cmdline argument
    # Remove any blank line so we can send proper string to the api_req()
    if args.file:
        file_arg = True

        formating_file()

    string = ""

    # Call the get_path function to have the path of the API Key File
    path = get_path(string)

    # If we receive nothing quit with error
    if path is None:
        exit(1)

    # Call the read_api_key function to read the API Key from the file
    api_key = read_api_key(path)

    # If we receive nothing quit with error
    if api_key is None:
        exit(1)

    # creating a bool to know if we need to call write_file_reputation_report()
    file_reputation = False

    # If user launched the script with the file cmdline arg
    # else then string cmdline argument scenario start
    if file_arg:
        data_list = args.file.readlines()  # Create a list with each elements on each line

        request = 0  # Initialize request var to check how many request we sent

        # Using for loop to sent each element of the list to the api request function
        for d in data_list:
            response = search_api_request(api_key, d)

            # If we receive nothing quit with error
            if response is None:
                exit(1)

            if parse_json(response, d, file_reputation) is True:
                write_file_reputation_report(api_key, d)

            request += 1

            if request == 4:
                print(
                    "\n[*] Sorry but the quota is 4 lookups/min, please wait 60 seconds...")
                # Should we use sleep or exit ? (more than 4 request works totally fine...)
                sleep(60)
                # exit(0)
    else:
        response = search_api_request(api_key, args.string)

        # If we receive nothing quit with error
        if response is None:
            exit(1)

        # check if we need to call file_reputation()
        if parse_json(response, args.string, file_reputation) is True:
            write_file_reputation_report(api_key, args.string)
            exit(0)
        else:
            exit(0)
