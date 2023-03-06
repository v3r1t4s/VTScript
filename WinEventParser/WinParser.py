"""import of modules"""
import re
import json
import main
import Helpers
import win32evtlog
import xml.etree.ElementTree as ET


def load_events_list_json(json_event_file):
    """Function used to loads events from the first json file"""
    try:
        with open(json_event_file, "r", encoding="UTF-8") as json_file:
            data_event_file_json = json.load(json_file)
            return data_event_file_json['events']
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
    return None


def checking_rules_id(ns, event_id_sample, time_created_sample, xml_sample, event_l, event_l_to_return_to_winparsermain):
    """sample function used to check rules list with selected events"""
    len_event_list = len(event_l)
    finding_something = None
    for rule in range(0, len_event_list):
        if int(event_id_sample) == event_l[rule]['ID']:
            finding_something = True
            
            ### NOT USABLE FOR NOW, MAYBE LATER ???
            #time_created_sample = time_created_sample.split('.', 1)[0]
            #time_created_sample = time_created_sample.replace('T', ' ')
            #time_created_sample = main.get_time_back_in_local(time_created_sample)
            #event_data_name_sample = xml_sample.find(f'.//{ns}EventData')                                                                                           # Get the EventData part of our event
            #try:
            #    for event_d_name_s in event_data_name_sample:
            #        # print(d.tag, d.attrib, d.text)
            #        if "TargetUserName" in str(event_d_name_s.attrib):                                                                                              # Check if it's credentials related like log on log off or special login
            #            event_l_to_return_to_winparsermain.append(f"[*] The event ID ({event_id_sample}) matched our rule list, the description of the rule is: {event_l[rule]['name']:}")
            #            event_l_to_return_to_winparsermain.append(f"[+] The TargetUsernName that interact with the machine was: {event_d_name_s.text}, it was registered at: {time_created_sample}")
            #except TypeError as t_error:
            #    Helpers.exception_handler(True, t_error)
            #    return None, None

    return finding_something, event_l_to_return_to_winparsermain

def WinParserMain(input_provided, timestamp, number_of_occurences):
    """Main function of WinParser Module"""
    event_list = load_events_list_json("EventIdAndNames.json")

    if event_list is None:
        print("[-] The file provided in the script can't be open.")
        exit(1)

    query_handle = win32evtlog.EvtQuery(r'C:\Windows\System32\winevt\Logs\Security.evtx', win32evtlog.EvtQueryFilePath)  # open event file

    read_count = 0
    display_only_one_event = True
    count_matched_event = 0
    event_list_to_return = []
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

            event_data = {"Time":time_created, "Computer":computer, "EventID":event_id, "Channel":channel, "ProcessID":process_id, "ThreadID":thread_id}
    
            if input_provided != "all":
                time_from_utc_to_local_zone = time_created.split('.', 1)
                time_from_utc_to_local_zone = time_from_utc_to_local_zone[0]
                time_from_utc_to_local_zone = time_from_utc_to_local_zone.replace('T', ' ')
                time_from_utc_to_local_zone = str(main.get_time_back_in_local(time_from_utc_to_local_zone))
                search_date_start = re.search((timestamp[0] + ".{"+f"{number_of_occurences[0]}"+"}"), time_from_utc_to_local_zone)

                search_date_end = re.search((timestamp[1] + ".{"+f"{number_of_occurences[1]}"+"}"), time_from_utc_to_local_zone)
                if search_date_start:
                    if search_date_end:
                        break
                    
                    found_something, event_list_to_return = checking_rules_id(ns, event_id, time_created, xml, event_list, event_list_to_return) 
                    if found_something is None and event_list_to_return is None:
                        return None
                    if found_something is True:
                        count_matched_event += 1
                        event_data = {"index":count_matched_event, "event":xml_content, "timestamp":time_created, "human_readable_time":time_from_utc_to_local_zone, "Computer":computer, "id":event_id, "Channel":channel, "ProcessID":process_id, "ThreadID":thread_id}
                        event_list_to_return.append(event_data)
                        #event_list_to_return.append(f"[*] (Event Nb {count_matched_event}) Full event data just here: " + xml_content)
            else:
                print(event_data)
    return event_list_to_return
