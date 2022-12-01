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


def input_and_parse_filename(filename_parsed, exclusion, excluded_character):
    """Function used to get a filename as input and parse it until we got a proper one"""
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
    """Function to make api request to search for a string"""
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
    res_dic = json.loads(res_parse_json)                                                                                                                                     # Loading the output into a dictionnary
    return res_dic


def parse_vt_response(res_dic):
    """Parse json response from VT to find errors and if none return the response"""
    if res_dic['data'] == []:                                                                                                                                                # Check if VT returns us something interesting when we query res_dic['data'], If not, return.
        print("[-] Sorry but VirusTotal didn't found something...\n")
        return 1, ""
    if "text" in res_dic['data'][0]['attributes']:                                                                                                                           # text is a unique key (in the dictionnary), only found in the response of a Tag comment specific API query, If we're finding this key return to main
        print("[*] Sorry but searching Tag Comment isn't available.\n[*] If you want to search one go there: https://www.virustotal.com/gui/home/search\n")
        return 1,  ""
    analysis_stat = res_dic['data'][0]['attributes']['last_analysis_stats']
    return 0, analysis_stat


def data_processing(string_parse_json, res_dic, analysis_stat, report_dic):
    """Function used to process data"""
    report_dic.append(f"-----------------------------------------------------------------------\n[*] Checking {string_parse_json}\n[*] Latest Analysis Statistics available counting the number of reports: {analysis_stat}\n")     # Parsing the output for last analysis statistics
    string_parse_json = string_parse_json.strip('\n')                                                                                                                                                                               # Removing \n character
    malicious = analysis_stat['malicious']
    if malicious:                                                                                                                                                                                                                   # Checking if malicious key has a hit
        report_dic.append(f"[*] Detailed reports about {string_parse_json} (engine name : result of the analysis): \n")
        analysis_res = res_dic['data'][0]['attributes']['last_analysis_results']                                                                                                                                                    # Preparing to parse the output for latest analysis results
        for value in analysis_res.values():                                                                                                                                                                                         # Parsing the output and checking every analysis made to find malicious one
            if "malicious" in value['category']:
                report_dic.append(f"[+] {value['engine_name']} : {value['result']}")
    report_dic.append(f"\n[+] {string_parse_json} was flagged {malicious} times.")
    is_string_hash = not ('.' in string_parse_json)                                                                                                                                                                                 # Checking if string provided was a hash
    if malicious >= 3 and is_string_hash is True:
        report_dic.append(f"\n[+] {string_parse_json} is definitely malicious\n")
        return 1, report_dic
    elif malicious:
        report_dic.append(f"\n[+] {string_parse_json} is definitely malicious\n")
    else:
        report_dic.append(f"[+] {string_parse_json} doesn't seems to be malicious.\n")
    return 0, report_dic


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


def handle_file_report(report_dic, string_argument, quota, file_argument, last_element):
    """Function used to handle our file report"""
    response = search_api_request(api_key, string_argument)
    if response is None:
        report_dic.append("[-] The search response we got had errors.")
        return 1, ""
    print(f"---------------------------------\n[*] Working on {string_argument}\n")
    response_dictionary = load_json(response)
    parse_json_error, analysis_stat = parse_vt_response(response_dictionary)
    if parse_json_error == 0:
        call_to_file_reputation, report_dic = data_processing(string_argument, response_dictionary, analysis_stat, report_dic)
        if call_to_file_reputation == 1:
            nb_of_request = 1
            if file_argument is True and last_element is False:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             # We provide either 1 or 2, depending if its a string or a file for the script argument and if file is it last element or not
                nb_of_request = 2
            if check_quota(quota, nb_of_request) is None:
                report_dic.append("[-] We had to skip the File reputation request because we exceeded the quota")
                return 0, report_dic
            response_file_reputation = file_reputation_api_request(api_key, string_argument)
            if response_file_reputation is None:
                report_dic.append("[-] The file reputation response we got had errors.")
                return 1, ""
            response_file_reputation = load_json(response_file_reputation)
            report_dic.append(f"[+] Getting you data of the file reputation response we got for {string_argument}:\n[*] The type_description of the hash is : {response_file_reputation['data']['attributes']['type_description']}\n[*] The hash was provided to VirusTotal by {str(response_file_reputation['data']['attributes']['unique_sources'])} unique sources\n[*] The most meaningful name of the hash file found by VirusTotal is: {response_file_reputation['data']['attributes']['meaningful_name']}\n[-] Check this link for more infos on your file: https://www.virustotal.com/gui/file/{string_argument}")
    return 0, report_dic

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


def handle_file(quota):
    """This function is used to handle the functions to create our file"""
    prompt_filename = ""
    filename = input_and_parse_filename(prompt_filename, True, '_')
    report_dic = []
    if file_arg:                                                                                    # If user launched the script with the file cmdline arg, else then string cmdline argument scenario start
        data_list = args.file.readlines()                                                           # Create a list with each elements on each line
        len_data_list = len(data_list)                                                              # Calculating length of our list
        count_of_each_argument = 1                                                                  # initialize the variable to 1 to catch the last element of the list
        for d in data_list:                                                                         # Using for loop to sent each element of the list to the api request function
            if count_of_each_argument != len_data_list:                                             # Using if to check if last eleemnt if not send false, if yes send True
                error, report_dic = handle_file_report(report_dic, d, quota, file_arg, False)
            else:
                error, report_dic = handle_file_report(report_dic, d, quota, file_arg, True)
            if error == 1:
                return 1
            count_of_each_argument += 1
    else:
        error, report_dic = handle_file_report(report_dic,  args.string, quota, file_arg, True)
        if error == 1:
            return 1
    for r in report_dic:
        append_data_to_a_file(filename, "txt", r)

    print(f"[+] The file report can be found as {filename}.txt in {Path.cwd()}")
    return 0

##########################################################
# HELPERS
##########################################################


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
        Helpers.exception_handler(True, strip_err)
        exit(1)
    return None


def get_path_from_user(prompt, text_for_input):
    """Get Path with input(), check if both path/file exist"""
    try:
        prompt = input(text_for_input)
        if Helpers.check_if_filepath_exists(prompt) is None:
            exit(1)
    except ValueError as val_err:
        Helpers.exception_handler(True, val_err)
        return None
    return prompt


def counting_lines_of_file(filename_to_count_to):
    """Function used to count number of lines in a file"""
    try:
        with open(filename_to_count_to, "r", encoding="UTF-8") as file:
            nb_of_lines = len(file.readlines())
            return nb_of_lines
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
    return None

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


def check_quota(quota_json, nb_requests_user_want):
    """Function used to check if we respect the quota"""
    quota_dic = load_json(quota_json)
    quota_monthly = quota_dic['data']['api_requests_monthly']['user']['allowed'] - quota_dic['data']['api_requests_monthly']['user']['used']
    if nb_requests_user_want > quota_monthly:
        print("[-] You already used your quota for the month come back later...")
        return None
    quota_daily = quota_dic['data']['api_requests_daily']['user']['allowed'] - quota_dic['data']['api_requests_daily']['user']['used']
    if nb_requests_user_want > quota_daily:
        print("[-] You already used your quota for the day come back later...")
        return None
    quota_hourly = quota_dic['data']['api_requests_hourly']['user']['allowed'] - quota_dic['data']['api_requests_hourly']['user']['used']
    if nb_requests_user_want > quota_hourly:
        print("[-] You already used your quota for the hour come back later...")
        return None
    return ""


if __name__ == '__main__':
    if verify_at_least_x_command_line_arguments(sys.argv, 1) is None:                                         # Check if an argument is provided
        print("[-] Please provide at least one command line argument(s)")
        exit(1)

    args = parse_arguments()

    file_arg = False                                                                                          # Set file argument to false until we know there's one

    number_of_arguments_to_check = 1

    if args.file:                                                                                             # Set to true if we find that it is used as cmdline argument, Remove any blank line so we can send proper string to the api_req()
        file_arg = True
        file_name = sys.argv[2]
        opening_file_stripping_new_lines(file_name)
        number_of_arguments_to_check = counting_lines_of_file(file_name)                                      # Counting the number of lines if we provide a file

    string = ""

    path = get_path_from_user(string, "Please input the absolute path of your API key configuration file: ")  # Call the get_path function to have the path of the API Key File

    if path is None:                                                                                          # If we receive nothing quit with error
        exit(1)

    api_key = Helpers.read_api_key(path)                                                                      # Call the read_api_key function to read the API Key from the file

    if api_key == '':                                                                                         # If we receive nothing quit with error
        print("[-] We couldn't find your API Key.")
        exit(1)

    response_quota = get_user_quota_summary(api_key)                                                          # Requesting the API for a quota usage summary

    if response_quota is None:
        exit(1)

    if check_quota(response_quota, number_of_arguments_to_check) is None:                                     # Calling check quota to check if the number of arguments we want to use for our API requests is greater than the quota available
        exit(1)

    if handle_file(response_quota) == 0:
        exit(0)

    exit(1)
