# Trims the list to only have the elements within the given timewindow (given in milliseconds)
def get_events_within_time_window(list_of_events_ordered_sequentially, start_event, index, rule):
    end_time = start_event["timestamp"] + rule["window"]
    start_index_list = list_of_events_ordered_sequentially[index+1:]  # Start at the next index since we don't want to re-process the same event
    for event in start_index_list: #index,
        if event["timestamp"] > end_time:                                 # This event is outside the Window
            return start_index_list[:index-1]                            # Return the list excluding this event and any occurring after it
    return start_index_list                                          # Should only reach here if end_time exceeds the last event timestamp


# Helper function that sets up all rule processing functions
def rule_preprocessor(list_of_events_ordered_sequentially, event, index, rule):
    detection = ""
    end_time = event["timestamp"] + rule["window"]
    events_within_window = get_events_within_time_window(list_of_events_ordered_sequentially, event, index, rule)
    return detection, end_time, events_within_window

# This function should iterate through the events starting with the first match
def process_counting_rule(list_of_events_ordered_sequentially, event, index, rule):
    detection, end_time, events_within_window = rule_preprocessor(list_of_events_ordered_sequentially, event, index, rule)
    count = 1  # Starts count at one since we already have the first match

    for window_event in events_within_window:
        if window_event["id"] == rule["ID"]:
            count = count + 1
    if count >= rule["required_count"]:
        detection = {rule["description"]: (event['timestamp'], event["human_readable_time"])}  # We can think about adding each event into this list
    return detection


# This function iterates through the events and looks for an ordered sequence of events
def process_ordered_rule(list_of_events_ordered_sequentially, event, index, rule):
    detection, end_time, events_within_window = rule_preprocessor(list_of_events_ordered_sequentially, event, index, rule)
    rule_index = 1                         # We need the event ID for the second event in the list of events
    current_rule_id = rule["IDs"][rule_index]  # Obtain the event ID for the next event we expect to see in the ordered list
    len_rule_ids = len(rule["IDs"])

    for window_event in get_events_within_time_window(list_of_events_ordered_sequentially, event, index, rule):
        if window_event["id"] == current_rule_id:
            rule_index = rule_index + 1
            if rule_index >= len_rule_ids:    # We matched the last event needed to trigger the rule
                detection = {rule["description"](event['timestamp'], event["human_readable_time"])}  # We can think about adding each event into this list
                return detection
            else:                             # We can continue processing
                current_rule_id = rule.ids[rule_index]  # Obtain the event ID for the next event we expect to see in the ordered list
    return detection

# This function iterates through the events and looks for a set of events
def process_unordered_rule(list_of_events_ordered_sequentially, event, index, rule):
    detection, end_time, events_within_window = rule_preprocessor(list_of_events_ordered_sequentially, event, index, rule)
    rule_ids = rule["IDs"]           # Obtain a copy of the list of events the rule needs to see

    for window_event in get_events_within_time_window(list_of_events_ordered_sequentially, event, index, rule):
        if window_event["id"] in rule_ids:
            rule_ids.remove(window_event["id"])  # Keep removing matched items until there are none left
    if len(rule_ids) < 1:
        detection = {rule["description"]: (event['timestamp'], event["human_readable_time"])}  # We can think about adding each event into this list
    return detection

# Processes rules for the analysis engine
def process_rule(list_of_events_ordered_sequentially, event, index, rule):
    detection = ""
    if rule["Type"] == "single_event":  # Since we're in this function, we automatically know we matched the first item in a rule
        detection = {rule['description']: (event['timestamp'], event["human_readable_time"])}
    elif rule["Type"] == "count":  # Same event multiple times
        detection = process_counting_rule(list_of_events_ordered_sequentially, event, index, rule)
    elif rule["Type"] == "ordered":  # A series of events, where all of them are in order
        detection = process_ordered_rule(list_of_events_ordered_sequentially, event, index, rule)
    elif rule["Type"] == "unordered":  # A series of events where the first is "ordered" and the rest can happen in any order within the window
        detection = process_unordered_rule(list_of_events_ordered_sequentially, event, index, rule)
    return detection

# The core of the analysis engine
def analysis_engine(list_of_events_ordered_sequentially, list_of_rules):
    detections = []
    for event in list_of_events_ordered_sequentially:
        for rule in list_of_rules:
            if int(event['id']) == rule['ID']:
                triggered_rule = process_rule(list_of_events_ordered_sequentially, event, event['index'], rule)
                if triggered_rule != "":
                    detections.append(triggered_rule)
    return detections
