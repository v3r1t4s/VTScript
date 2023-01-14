"""import of modules"""
import re
import json
import ctypes
import Helpers
import datetime
from dateutil import tz
import win32evtlog
import xml.etree.ElementTree as ET


def admin():
    """Function used to check if the person running the Windows environnment is admin"""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == 1:
            return True
        else:
            return False
    except NameError:
        return False


def parse_timestamp(timestamp_to_be_parsed, mode):
    """Function used to parse the input timestamp we had"""
    if timestamp_to_be_parsed is None:
        return None, None
    timestamp_to_be_parsed = timestamp_to_be_parsed.split()
    if len(timestamp_to_be_parsed) == 2:
        timestamp_to_be_parsed = timestamp_to_be_parsed[0] + ' ' + timestamp_to_be_parsed[1]
    else:
        timestamp_to_be_parsed = timestamp_to_be_parsed[0]
    acceptable_chars = ['-', ' ', ':']
    for ttbp in timestamp_to_be_parsed:
        if (ttbp.isdigit() or ttbp in acceptable_chars) is not True:
            return None, None
    try:
        chars_to_add = ""
        len_to_remove = 0
        match mode:
            case 2:
                chars_to_add = ":00"
                len_to_remove = len(chars_to_add)
            case 3:
                chars_to_add = ":00:00"
                len_to_remove = len(chars_to_add)
            case 4:
                chars_to_add = " 00:00:00"
                len_to_remove = len(chars_to_add)
            case 5:
                chars_to_add = "-01 00:00:00"
                len_to_remove = len(chars_to_add)
            case 6:
                chars_to_add = "-01-01 00:00:00"
                len_to_remove = len(chars_to_add)
        timestamp_parsed = datetime.datetime.strptime(timestamp_to_be_parsed + chars_to_add, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None, None
    return timestamp_parsed, len_to_remove


def convert_time_in_utc(time_local_timezone):
    """Function used to convert the timestamp we were given in UTC, time zone used by the logs of windows"""
    try:
        time_datetime_type = datetime.datetime.strptime(time_local_timezone, "%Y-%m-%d %H:%M:%S")
        time_utc_raw = time_datetime_type.astimezone(datetime.timezone.utc)
        time_utc = time_utc_raw.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return time_utc


def get_input_timestamp(input_mode_timestamp):
    """Function used to get the timestamp the user want to check the events"""
    try:
        prompt = None
        num_of_timestamp = 0
        if input_mode_timestamp == "two":
            num_of_timestamp = 2
        else:
            num_of_timestamp = 1
        mode_to_pass = ""
        mode_to_check = ["1", "2", "3", "4", "5", "6"]
        timestamp_utc = []
        len_timestamp_input = []
        iteration_of_for_loop = 1
        for n_o_t in range(0, num_of_timestamp):
            while mode_to_pass not in mode_to_check:
                mode_to_pass = input(f"[{iteration_of_for_loop}] Please when you input your timestamp do you want to input 1) a full timestamp, 2) a timestamp with date, hour and minute, 3) a timestamp with date and hour, 4) a timestamp with date only, 5) a timestamp with year and month, 6) a timestamp with year (1/2/3/4/5/6): ")
            timestamp_parsed = None
            while timestamp_parsed is None:
                prompt = input(f"[{iteration_of_for_loop}] Please input the timestamp to use for searching events: ")
                timestamp_parsed, len_to_remove = parse_timestamp(prompt, int(mode_to_pass))
            mode_to_pass = ""
            len_timestamp_input.append(len_to_remove)
            timestamp_parsed = str(timestamp_parsed)
            timestamp_utc.append(timestamp_parsed)
            if timestamp_utc is None:
                return None
            iteration_of_for_loop += 1
        return timestamp_utc, len_timestamp_input
    except ValueError as val_err:
        Helpers.exception_handler(True, val_err)
        return None


def load_events_list_json(json_event_file):
    """Read API Key from the file path provided in get_path()"""
    try:
        with open(json_event_file, "r", encoding="UTF-8") as json_file:
            data_event_file_json = json.load(json_file)
            return data_event_file_json['events']
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
    return None


def get_time_back_in_local(utc_time):
    """Function used to convert back from UTC to local time zone"""
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()                                              # Auto-detect zones:
    utc = datetime.datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S')
    utc = utc.replace(tzinfo=from_zone)                                 # Tell the datetime object that it's in UTC time zone since datetime objects are 'naive' by default
    local_time = utc.astimezone(to_zone)                                # Convert time zone
    return local_time


def checking_rules_id(event_id_sample, time_created_sample, xml_sample, event_l):
    """sample function used to check rules list with selected events"""
    len_event_list = len(event_l)
    for rule in range(0, len_event_list):
        if int(event_id_sample) == event_l[rule]['ID']:
            time_created_sample = time_created_sample.split('.', 1)[0]
            time_created_sample = time_created_sample.replace('T', ' ')
            time_created_sample = get_time_back_in_local(time_created_sample)
            event_data_name_sample = xml_sample.find(f'.//{ns}EventData')                                                                                           # Get the EventData part of our event
            try:
                for event_d_name_s in event_data_name_sample:
                    # print(d.tag, d.attrib, d.text)
                    if "TargetUserName" in str(event_d_name_s.attrib):                                                                                              # Check if it's credentials related like log on log off or special login
                        print(f"[*] The event ID ({event_id_sample}) matched our rule list, the description of the rule is: {event_l[rule]['name']:}")
                        print(f"[+] The TargetUsernName that interact with the machine was: {event_d_name_s.text}, it was registered at: {time_created_sample}")
            except TypeError as t_error:
                Helpers.exception_handler(True, t_error)
                return None


if __name__ == '__main__':
    if admin() is False:
        print("[-] You should run the script as admin!")
        exit(1)

    input_modes = ["all", "one", "two"]
    input_provided = ""
    while input_provided not in input_modes:
        try:
            input_provided = input("Do you want to input 1) nothing, display all events please, 2) one timestamp that give every events during this time or 3) two timestamps that act as bracket to search for events between two specific times (all/one/two): ")
        except ValueError:
            continue
    if input_provided != "all":
        timestamp_raw, len_to_remove_to_timestamp = get_input_timestamp(input_provided)
        if timestamp_raw is None:
            print("[-] You should try to run the script and input a timestamp again.")
            exit(1)
        num_timestamp_factoring = 0
        if input_provided == "one":
            num_timestamp_factoring = 1
        elif input_provided == "two":
            num_timestamp_factoring = 2
        if num_timestamp_factoring != 0:
            timestamp = ["", ""]
            number_of_occurences = ["", ""]
            for n_t_f in range(0, num_timestamp_factoring):
                timestamp[n_t_f] = timestamp_raw[n_t_f]
                timestamp_temp = ["", ""]
                counting_char_timestamp = 0
                for t in timestamp[n_t_f]:
                    if counting_char_timestamp != 19 - len_to_remove_to_timestamp[n_t_f]:
                        timestamp_temp[n_t_f] += t
                        counting_char_timestamp += 1
                timestamp[n_t_f] = timestamp_temp[n_t_f]
                number_of_occurences[n_t_f] = len_to_remove_to_timestamp[n_t_f]

    event_list = load_events_list_json("EventIdAndNames.json")

    if event_list is None:
        print("[-] The file provided in the script can't be open.")
        exit(1)

    query_handle = win32evtlog.EvtQuery(r'C:\Windows\System32\winevt\Logs\Security.evtx', win32evtlog.EvtQueryFilePath)  # open event file

    read_count = 0
    display_only_one_event = True
    count_matched_event = 0

    while display_only_one_event is True:
        # display_only_one_event = False                                                                                                                               # read 1 record(s)
        events = win32evtlog.EvtNext(query_handle, 1)
        read_count += len(events)
        if len(events) == 0:                                                                                                                                           # if there is no record break the loop
            break

        for event in events:
            xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

            xml = ET.fromstring(xml_content)                                                                                                                           # parse xml content

            # print(xml_content)                                                                                                                                       # Print the whole xml event

            ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'                                                                                             # xml namespace, root element has a xmlns definition, so we have to use the namespace

            event_id = xml.find(f'.//{ns}EventID').text
            computer = xml.find(f'.//{ns}Computer').text
            channel = xml.find(f'.//{ns}Channel').text
            execution = xml.find(f'.//{ns}Execution')
            process_id = execution.get('ProcessID')
            thread_id = execution.get('ThreadID')
            time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')

            event_data = f"Time: {time_created}, Computer: {computer}, Event Id: {event_id}, Channel: {channel}, Process Id: {process_id}, Thread Id: {thread_id}"

            if input_provided != "all":
                time_from_utc_to_local_zone = time_created.split('.', 1)
                time_from_utc_to_local_zone = time_from_utc_to_local_zone[0]
                time_from_utc_to_local_zone = time_from_utc_to_local_zone.replace('T', ' ')
                time_from_utc_to_local_zone = str(get_time_back_in_local(time_from_utc_to_local_zone))
                search_date_start = re.search((timestamp[0] + ".{"+f"{number_of_occurences[0]}"+"}"), time_from_utc_to_local_zone)

                search_date_end = re.search((timestamp[1] + ".{"+f"{number_of_occurences[1]}"+"}"), time_from_utc_to_local_zone)
                if search_date_start:
                    if search_date_end:
                        break
                    f = open("FILE.txt", "a", encoding="UTF-8")
                    f.write(time_created + "\n")
                    f.close()
                    count_matched_event += 1
                    print(f"[*] (Event Nb {count_matched_event} found in the timestamp provided): " + event_data)
                    if checking_rules_id(event_id, time_created, xml, event_list) is None:
                        print("[-] This event wasn't interesting")

            else:
                f = open("FILE.txt", "a", encoding="UTF-8")
                f.write(time_created + "\n")
                f.close()
                print(event_data)
    exit(0)
