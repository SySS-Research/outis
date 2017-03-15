
def isint(value):
    if value and str(value).isdigit():
        return True
    else:
        return False


def isportnumber(value):
    if not value or not str(value).isdigit() or int(value) < 1 or int(value) > 65535:
        return False
    else:
        return True
