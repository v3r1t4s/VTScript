import os
import sys

# This function ehances default Python Error handling
# It will print the line in code that the error occurred on


def exception_handler(print_exception=False, exception=""):
    if print_exception == True:
        print(exception)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("Exception on line: ", exc_tb.tb_lineno, " in ", fname)
    return
