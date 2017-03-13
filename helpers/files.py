
import os.path


def sanatizefilename(filename):
    toolpath = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return filename.replace("$TOOLPATH", toolpath)
