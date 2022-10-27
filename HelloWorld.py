import Helpers




if __name__ == '__main__':
  print("Hello World")
  try:
    f = open("ERROR_TEST.txt") #MAGIC NUMBER / STRING
  except Exception as e:
    Helpers.exception_handler(True, e)
  print("We safely returned from error handling")
  exit(0) #Exitted normally/successfully
  exit(1) #Process exited with a failure
