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


def checking_arguments(arguments):
    """Function checking the number of arguments"""
    if len(arguments) > 1:
        return arguments
    return


def get_path(prompt):
    """Get Path with input(), check if both path/file exist"""

    try:
        prompt = input("Please input the absolute path of your API key configuration file: ")
        if os.path.exists(prompt):
            print("[+] The path is valid!")
            prompt = Path(prompt)

            if prompt.is_file():
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

    if response_search_api.status_code == 400:
        print(
            f"[-] HTTP response wasn't successful: {response_search_api.status_code}, made too many request need to wait 60 seconds...")
        sleep(60)
        search_api_request(key, data)

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

    if response_file_reputation.status_code == 400:
        print(
            f"[-] HTTP response wasn't successful: {response_file_reputation.status_code}, made too many request need to wait 60 seconds...")
        sleep(60)
        file_reputation_api_request(key, hash_file_reputation)

    print(
        f"[-] HTTP response wasn't successful: {response_file_reputation.status_code}")
    return


def parse_json(res_parse_json, string_parse_json, file_reputation_parse_json, filename_report):
    """Parse json response from VT to find malicious signs"""

    print(f"[*] Working on {string_parse_json}...\n")  # Print the line to separate each parsing when having multiple responses and Printing out the string that's being parsed at this time
    append_report(filename_report, f"------------------------------------------------------------------------------------- \n\n[*] Checking {string_parse_json}\n")  # Print the line to separate each parsing when having multiple responses and Printing out the string that's being parsed at this time

    string_parse_json = string_parse_json.replace('\n', '')  # Removing \n character

    res_dic = json.loads(res_parse_json)  # Loading the output into a dictionnary

    if res_dic['data'] == []:  # Check if VT returns us something interesting when we query api_req(), If not, return.
        append_report(filename_report, "[-] Sorry but VirusTotal didn't found something...\n")
        return

    if "text" in res_dic['data'][0]['attributes']:  # text is a unique key (in the dictionnary), only found in the response of a Tag comment specific API query, If we're finding this key return to main
        append_report(filename_report, "[*] Sorry but searching Tag Comment isn't available.")
        append_report(filename_report, "[*] If you want to search one go there: https://www.virustotal.com/gui/home/search\n")
        return

    analysis_stat = res_dic['data'][0]['attributes']['last_analysis_stats']  # Parsing the output for last analysis statistics

    append_report(filename_report, f"[*] Latest Analysis Statistics available counting the number of reports: {analysis_stat}\n")

    malicious = analysis_stat['malicious']

    if malicious:  # Checking if malicious key has a hit
        append_report(filename_report, f"[*] Detailed reports about {string_parse_json} (engine name : result of the analysis): \n")

        analysis_res = res_dic['data'][0]['attributes']['last_analysis_results']  # Preparing to parse the output for latest analysis results

        for value in analysis_res.values():  # Parsing the output and checking every analysis made to find malicious one
            if "malicious" in value['category']:
                append_report(filename_report, f"[+] {value['engine_name']} : {value['result']}")

    append_report(filename_report, "\n[+] You can find the full report from the search request here: \n")
    append_report(filename_report, res_parse_json)

    append_report(filename_report, f"\n[+] The string was flagged {malicious} times.")

    check_hash = '.' in string_parse_json  # Checking if string provided was a hash

    if malicious >= 3 and check_hash is not True:
        append_report(filename_report, f"\n[+] {string_parse_json} is definitely malicious\n")

        file_reputation_parse_json = True

        return file_reputation_parse_json
    elif malicious:
        append_report(filename_report, f"\n[+] {string_parse_json} is definitely malicious\n")
    else:
        append_report(filename_report, "[+] This doesn't seems to be malicious.\n")

    return


def parse_filename(filename_parsed):
    """Function used to get a filename as input and parse it until we got a proper one"""

    while filename_parsed.isalnum() is False:
        try:
            filename = input(
                "Please provide a filename for your report (without an extension / _ is accepted between chars): ")

            filename_parsed = filename

            if filename != '':
                if filename[0] != '_' and filename[-1] != '_' and filename.count('_') == 1:
                    filename_parsed = filename.replace('_', '')

        except ValueError as val_err:
            exception_handler(True, val_err)
            return

    return filename


def append_report(filename_to_append_to, data_to_write):
    """Writing/Appending data to our report"""

    try:
        with open(f"{filename_to_append_to}.txt", "a", encoding="UTF-8") as file:
            file.write(data_to_write + "\n")
    except IOError as io_err:
        exception_handler(True, io_err)
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

    return


def logic_func():
    """Creating our logic for calling our functions"""

    prompt_filename = ""

    filename = parse_filename(prompt_filename)

    file_reputation = False  # creating a bool to know if we need to call write_file_reputation_report()

    if file_arg:  # If user launched the script with the file cmdline arg, else then string cmdline argument scenario start
        data_list = args.file.readlines()  # Create a list with each elements on each line

        for d in data_list:  # Using for loop to sent each element of the list to the api request function
            response = search_api_request(api_key, d)

            if response is None:  # If we receive nothing quit with error
                print("[-] We didn't receive something from our search request.")
                exit(1)

            if parse_json(response, d, file_reputation, filename) is True:
                response_file_reputation = file_reputation_api_request(api_key, d)
                append_report(filename, "[+] Response from File reputation request: \n")
                append_report(filename, response_file_reputation)

    else:
        response = search_api_request(api_key, args.string)

        if response is None:  # If we receive nothing quit with error
            exit(1)

        if parse_json(response, args.string, file_reputation, filename) is True:  # check if we need to call write_report() for file reputation
            response_file_reputation = file_reputation_api_request(api_key, args.string)
            append_report(filename, "[+] Response from File reputation request: \n")
            append_report(filename, response_file_reputation)

    print(
        f"[+] The file report can be found as {filename}.txt in {Path.cwd()}")

    exit(0)


if __name__ == '__main__':

    if checking_arguments(sys.argv) is None:  # Check if an argument is provided
        print("[-] Please provide at least one command line argument")
        exit(1)

    parser = argparse.ArgumentParser()  # Create the parser to have arguments in the script

    parser.add_argument('--string', type=str, )  # Adding string argument

    parser.add_argument('--file', type=argparse.FileType('r'))  # Adding File argument

    args = parser.parse_args()  # Parse the argument

    file_arg = False  # Set file argument to false until we know there's one

    if args.file:  # Set to true if we find that it is used as cmdline argument, Remove any blank line so we can send proper string to the api_req()
        file_arg = True

        formating_file()

    string = ""

    path = get_path(string)  # Call the get_path function to have the path of the API Key File

    if path is None:  # If we receive nothing quit with error
        print("[-] We didn't receive a proper path from the function")
        exit(1)

    api_key = read_api_key(path)  # Call the read_api_key function to read the API Key from the file

    if api_key == '':  # If we receive nothing quit with error
        print("[-] We couldn't find your API Key.")
        exit(1)

    logic_func()
