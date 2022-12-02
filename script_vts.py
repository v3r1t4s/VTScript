"""import of modules"""
import sys
import json
import Helpers
import argparse
import requests
from pathlib import Path

##########################################################
# DATA HANDLING
##########################################################


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
    return filename


def search_api_request(key, data):
    """Function used to make api request to search for a string"""
    url = f"https://www.virustotal.com/api/v3/search?query={data}"
    headers = {"accept": "application/json",
               "x-apikey": key
               }
    response_search_api = requests.get(url, headers=headers, timeout=10)
    if response_search_api.status_code == 200:
        return response_search_api.text
    print(f"[-] HTTP response wasn't successful: {response_search_api.status_code}, here's the full response we got: \n{response_search_api.text}")
    return None


def load_json(res_parse_json):
    """Load json string and convert it into a dictionnary"""
    res_dic = json.loads(res_parse_json)                       # Loading the output into a dictionnary
    return res_dic


def parse_vt_response(res_dic, string_argument):
    """Parse json response from VT to find errors and if none return the response"""
    if res_dic['data'] == []:                                                                                                                                                # Check if VT returns us something interesting when we query res_dic['data'], If not, return.
        print("[-] Sorry but VirusTotal didn't found something...\n")
        len_argument = len(string_argument)
        if len_argument == 33 or len_argument == 41 or len_argument == 65:                                                                                                   # Checking length of string provided, VT accept only MD5, SHA-1 and SHA256, it's the three lengths of those hash type that we check
            if string_argument.isupper():
                print("[*] Maybe you should try to provide your hash again in lowercase\n")
        return 1, ""
    if "text" in res_dic['data'][0]['attributes']:                                                                                                                           # text is a unique key (in the dictionnary), only found in the response of a Tag comment specific API query, If we're finding this key return to main
        print("[*] Sorry but searching Tag Comment isn't available.\n[*] If you want to search one go there: https://www.virustotal.com/gui/home/search\n")
        return 1,  ""
    analysis_stat = res_dic['data'][0]['attributes']['last_analysis_stats']
    return 0, analysis_stat


def data_processing(string_parse_json, res_dic, analysis_stat, report_dictionary):
    """Function used to process data"""
    report_dictionary.append(f"-----------------------------------------------------------------------\n[*] Checking {string_parse_json}\n[*] Latest Analysis Statistics available counting the number of reports: {analysis_stat}\n")     # Parsing the output for last analysis statistics
    string_parse_json = string_parse_json.strip('\n')                                                                                                                                                                                      # Removing \n character
    malicious = analysis_stat['malicious']
    malicious_count = 0
    if malicious:                                                                                                                                                                                                                          # Checking if malicious key has a hit
        report_dictionary.append(f"[*] Detailed reports about {string_parse_json} (engine name : result of the analysis): ")
        analysis_res = res_dic['data'][0]['attributes']['last_analysis_results']                                                                                                                                                           # Preparing the output for latest analysis results
        for value in analysis_res.values():                                                                                                                                                                                                # Analyzing the output and checking every analysis made to find malicious one
            if "malicious" in value['category']:
                report_dictionary.append(f"[+] {value['engine_name']} : {value['result']}")
                malicious_count += 1
    report_dictionary.append(f"\n[+] {string_parse_json} was flagged {malicious} times.")
    is_string_hash = not ('.' in string_parse_json)                                                                                                                                                                                        # Checking if string provided was a hash
    if malicious_count >= 3 and is_string_hash is True:
        report_dictionary.append(f"[+] {string_parse_json} is definitely malicious\n")
        return 1, report_dictionary
    elif malicious:
        report_dictionary.append(f"[+] {string_parse_json} is definitely malicious\n")
    else:
        report_dictionary.append(f"[+] {string_parse_json} doesn't seems to be malicious.\n")
    return 0, report_dictionary


def file_reputation_api_request(key, hash_file_reputation):
    """Function to make api request to get a file report"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_file_reputation}"
    headers = {"accept": "application/json",
               "x-apikey": key
               }
    response_file_reputation = requests.get(url, headers=headers, timeout=10)
    if response_file_reputation.status_code == 200:
        return response_file_reputation.text
    print(f"[-] HTTP response wasn't successful: {response_file_reputation.status_code}, here's the full response we got: {response_file_reputation.text}")
    return None


def get_vt_data(api_key_to_use, string_argument, report_dictionary, api_request_type):
    """Function used to get VT data by calling either of the function below that query VT API"""
    if api_request_type == "SEARCH":
        search_response = search_api_request(api_key_to_use, string_argument)
        if search_response is None:
            report_dictionary.append("[-] The search response we got had errors.")
            return 1, report_dictionary
        return 0, search_response
    if api_request_type == "FILE":
        file_reputation_response = file_reputation_api_request(api_key_to_use, string_argument)
        if file_reputation_response is None:
            report_dictionary.append("[-] The file reputation response we got had errors.")
            return 1, report_dictionary
        return 0, file_reputation_response
    return 1, ""


def create_file_report(report_dictionary, string_argument, quota, api_key_to_use):
    """Function used to handle our file report"""
    print(f"---------------------------------\n[*] Working on {string_argument}\n")
    num_of_requests = 2
    if check_quota(quota, num_of_requests) is None:
        report_dictionary.append("[-] We've run out of quota")
        return 0, report_dictionary
    get_vt_data_error, search_response = get_vt_data(api_key_to_use, string_argument, report_dictionary, "SEARCH")
    if get_vt_data_error == 1:
        return 0, search_response
    response_dictionary = load_json(search_response)
    parse_vt_response_error, analysis_stat = parse_vt_response(response_dictionary, string_argument)
    if parse_vt_response_error == 0:
        call_to_file_reputation, report_dictionary = data_processing(string_argument, response_dictionary, analysis_stat, report_dictionary)
        if call_to_file_reputation == 1:
            get_vt_data_error, file_reputation_response = get_vt_data(api_key_to_use, string_argument, report_dictionary, "FILE")
            if get_vt_data_error == 1:
                return 0, file_reputation_response
            file_reputation_response = load_json(file_reputation_response)
            report_dictionary.append(f"[+] Getting you data of the file reputation response we got for {string_argument}:\n[*] The type_description of the hash is : {file_reputation_response['data']['attributes']['type_description']}\n[*] The hash was provided to VirusTotal by {str(file_reputation_response['data']['attributes']['unique_sources'])} unique sources\n[*] The most meaningful name of the hash file found by VirusTotal is: {file_reputation_response['data']['attributes']['meaningful_name']}\n[-] Check this link for more infos on your file: https://www.virustotal.com/gui/file/{string_argument}")
    return 0, report_dictionary

##########################################################
# DATA FORMATTING + FILE WRITE
##########################################################


def append_data_to_a_file(filename_to_append_to, file_type, data_to_write):
    """Appending data to a file"""
    try:
        with open(f"{filename_to_append_to}.{file_type}", "a", encoding="UTF-8") as file:
            file.write(data_to_write + "\n")
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
    return None


def handle_file(quota, api_key_to_use):
    """This function is used to handle the functions to create our file"""
    filename = get_user_input_and_parse_filename(True, '_')
    report_dictionary = []
    if file_arg:                                                                                                                                    # If user launched the script with the file cmdline arg, else then string cmdline argument scenario start
        data_list = args.file.readlines()                                                                                                           # Create a list with each elements on each line
        for d in data_list:                                                                                                                         # Using for loop to sent each element of the list to the api request function
            handle_file_report_error, report_dictionary = create_file_report(report_dictionary, d, quota, api_key_to_use)
            if handle_file_report_error == 1:
                return 1, "", ""
    else:
        handle_file_report_error, report_dictionary = create_file_report(report_dictionary,  args.string, quota, api_key_to_use)
        if handle_file_report_error == 1:
            return 1, "", ""
    print(f"[+] The file report can be found as {filename}.txt in {Path.cwd()}")
    return 0, filename, report_dictionary

##########################################################
# HELPERS
##########################################################


##########################################################
# MAIN AND SETUP
##########################################################


def parse_arguments():
    """Function used to parse arguments"""
    parser = argparse.ArgumentParser()                          # Create the parser to have arguments in the script
    parser.add_argument('--string', type=str, )                 # Adding string argument
    parser.add_argument('--file', type=argparse.FileType('r'))  # Adding File argument
    return parser.parse_args()                                  # Parse the argument


def get_user_quota_summary(key):
    """Function used to query VT API about our quota"""
    url = f"https://www.virustotal.com/api/v3/users/{key}/overall_quotas"
    headers = {
        "accept": "application/json",
        "x-apikey": key
    }
    response_get_user_quota_summary = requests.get(url, headers=headers, timeout=10)
    if response_get_user_quota_summary.status_code == 200:
        return response_get_user_quota_summary.text
    print(f"[-] HTTP response wasn't successful: {response_get_user_quota_summary.status_code}, here's the full response we got: {response_get_user_quota_summary.text}")
    return None


def check_quota(quota_json, num_requests):
    """Function used to check if we respect the quota"""
    quota_dic = load_json(quota_json)
    quota_monthly = quota_dic['data']['api_requests_monthly']['user']['allowed'] - quota_dic['data']['api_requests_monthly']['user']['used']
    if num_requests > quota_monthly:
        print("[-] You already used your quota for the month come back later...")
        return None
    quota_daily = quota_dic['data']['api_requests_daily']['user']['allowed'] - quota_dic['data']['api_requests_daily']['user']['used']
    if num_requests > quota_daily:
        print("[-] You already used your quota for the day come back later...")
        return None
    quota_hourly = quota_dic['data']['api_requests_hourly']['user']['allowed'] - quota_dic['data']['api_requests_hourly']['user']['used']
    if num_requests > quota_hourly:
        print("[-] You already used your quota for the hour come back later...")
        return None
    return ""


if __name__ == '__main__':
    if Helpers.verify_at_least_x_command_line_arguments(sys.argv, 1) is None:                                 # Check if an argument is provided
        print("[-] Please provide at least one command line argument(s)")
        exit(1)

    args = parse_arguments()

    file_arg = False                                                                                          # Set file argument to false until we know there's one

    num_requests_user_want = 2

    if args.file:                                                                                             # Set to true if we find that it is used as cmdline argument, Remove any blank line so we can send proper string to the api_req()
        file_arg = True
        file_name = sys.argv[2]
        Helpers.opening_file_stripping_new_lines(file_name)
        num_requests_user_want = Helpers.counting_lines_of_file(file_name) * 2                                # Counting the number of lines if we provide a file

    path = Helpers.get_path_from_user("Please input the absolute path of your API key configuration file: ")  # Call the get_path_from_user function to have the path of the API Key File

    if path is None:                                                                                          # If we receive nothing quit with error
        exit(1)

    api_key = Helpers.read_api_key(path)                                                                      # Call the read_api_key function to read the API Key from the file

    if api_key == '':                                                                                         # If we receive nothing quit with error
        print("[-] We couldn't find your API Key.")
        exit(1)

    response_quota = get_user_quota_summary(api_key)                                                          # Requesting the API for a quota usage summary

    if response_quota is None:
        exit(1)

    if check_quota(response_quota,  num_requests_user_want) is None:                                          # Calling check quota to check if the number of arguments we want to use for our API requests is greater than the quota available
        exit(1)

    handle_file_error, filename_report, report = handle_file(response_quota, api_key)

    if handle_file_error == 0:
        for r in report:
            append_data_to_a_file(filename_report, "txt", r)
        exit(0)

    exit(1)
