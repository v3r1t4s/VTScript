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
        return None
    acceptable_chars = ['-', ' ', ':']
    for ttbp in timestamp_to_be_parsed:
        if (ttbp.isdigit() or ttbp in acceptable_chars) is not True:
            return None
    try:
        numbers_to_add = ""
        if mode == 3:
            numbers_to_add = ":0"
        elif mode == 4:
            numbers_to_add = ":0:0"
        timestamp_parsed = datetime.datetime.strptime(timestamp_to_be_parsed + numbers_to_add, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return timestamp_parsed


def convert_time_in_utc(time_local_timezone, input_mode_timestamp):
    """Function used to convert the timestamp we were given in UTC, time zone used by the logs of windows"""
    try:
        numbers_to_add_utc = ""
        if input_mode_timestamp == 3:
            numbers_to_add_utc = ":0"
        if input_mode_timestamp == 4:
            numbers_to_add_utc = ":0:0"
        time_datetime_type = datetime.datetime.strptime(time_local_timezone + numbers_to_add_utc, "%Y-%m-%d %H:%M:%S")
        time_utc_raw = time_datetime_type.astimezone(datetime.timezone.utc)
        time_utc = time_utc_raw.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return time_utc


def get_input_timestamp(input_mode_timestamp):
    """Function used to get the timestamp the user want to check the events"""
    try:
        prompt = None
        while parse_timestamp(prompt, input_mode_timestamp) is None:
            prompt = input("Please input the timestamp to use for searching events, (in 24h format) : ")
        len_timestamp_input = len(prompt)
        timestamp_utc = convert_time_in_utc(prompt, input_mode_timestamp)
        if timestamp_utc is None:
            return None
    except ValueError as val_err:
        Helpers.exception_handler(True, val_err)
        return None
    return timestamp_utc, len_timestamp_input


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
    # utc = datetime.utcnow()
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
            event_data_name_sample = xml_sample.find(f'.//{ns}EventData')                                                                                       # Get the EventData part of our event
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

    input_mode = 0
    while input_mode > 4 or input_mode <= 0:
        try:
            input_mode = int(input("Do you want to input 1) nothing, display all events please, 2) a timestamp in normal mode (like this 2023-01-04 20:51:14), 3) a timestamp with date, hour and minute (like this 2023-01-04 20:51) 4) a timestamp with only date and hour (like this 2023-01-04 20) (1/2/3/4): "))
        except ValueError:
            continue
    if input_mode != 1:
        timestamp_raw, len_input = get_input_timestamp(input_mode)

        if timestamp_raw is None:
            print("[-] You should try to run the script and input a timestamp again.")
            exit(1)

        timestamp = timestamp_raw.replace(' ', 'T')
        timestamp_temp = ""
        counting_char_timestamp = 0
        for t in timestamp:
            if counting_char_timestamp != len_input + 2:
                timestamp_temp += t
                counting_char_timestamp += 1
        timestamp = timestamp_temp

        number_of_occurences = 28 - len(timestamp)

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

            if input_mode != 1:
                if re.search((timestamp + ".{"+f"{number_of_occurences}"+"}"), time_created):
                    count_matched_event += 1
                    print(f"[*] (Event Nb {count_matched_event} found in the timestamp provided): " + event_data)
                    if checking_rules_id(event_id, time_created, xml, event_list) is None:
                        print("[-] This event wasn't interesting")
            else:
                print(event_data)
    exit(0)
