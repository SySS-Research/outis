
def isportnumber(value):
    if not value or not str(value).isdigit() or int(value) < 1 or int(value) > 65535:
        return False
    else:
        return True
