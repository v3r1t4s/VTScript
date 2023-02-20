"""import of modules"""
import json
import time
import Helpers


def load_rules_list_json(json_event_file):
    """Read API Key from the file path provided in get_path()"""
    try:
        with open(json_event_file, "r", encoding="UTF-8") as json_file:
            data_event_file_json = json.load(json_file)
            return data_event_file_json['rules']
    except IOError as io_err:
        Helpers.exception_handler(True, io_err)
    return None


def WinParserMain(event_list):
    rules = load_rules_list_json("AnalysisRules.json")
    if rules is None:
        print("[-] The file provided in the script can't be open.")
        exit(1)

    # A dictionary to keep track of the count of events for each ID
    event_counts = {}
    
    data_to_return = []

    # Loop through each event
    for event in event_list:
        event_id = int(event['EventID'])

        # Get the matching rule for this event ID
        rule = next((r for r in rules if r['ID'] == event_id), None)
        if not rule:
            # No matching rule found, skip this event
            continue
    
        # Check if the count and timeframe conditions are met
        if 'count' in rule and 'timeframe' in rule:
            now = time.time()
            timeframe = int(rule['timeframe'].split()[0]) * 60
            if event_id in event_counts:
                event_counts[event_id]['count'] += 1
                if now - event_counts[event_id]['timestamp'] > timeframe:
                    event_counts[event_id]['count'] = 1
                    event_counts[event_id]['timestamp'] = now
                if event_counts[event_id]['count'] >= rule['count']:
                    # Perform the action specified in the rule
                    if rule['action'] == 'log':
                        # Log the event
                        #print(f'Event ID {event_id}: {rule["description"]}')
                        data_to_return.append(f'Event ID {event_id}: {rule["description"]}')
                        data_to_return.append(str(event))
                    elif rule['action'] == 'alert':
                        # Send an alert
                        #print(f'ALERT: Event ID {event_id}: {rule["description"]}')
                        data_to_return.append(f'ALERT: Event ID {event_id}: {rule["description"]}')
                        data_to_return.append(str(event))
            else:
                event_counts[event_id] = {
                    'count': 1,
                    'timestamp': now
                }
        """else:
            # Perform the action specified in the rule
            if rule['action'] == 'log':
                # Log the event
                #print(f'Event ID {event_id}: {rule["description"]}')
                data_to_return.append(f'Event ID {event_id}: {rule["description"]}')
                data_to_return.append(str(event))
            elif rule['action'] == 'alert':
                # Send an alert
                #print(f'ALERT: Event ID {event_id}: {rule["description"]}')
                data_to_return.append(f'ALERT: Event ID {event_id}: {rule["description"]}')
                data_to_return.append(str(event))
        """
    #print(event_list)
    return data_to_return
