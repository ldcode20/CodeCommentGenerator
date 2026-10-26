# This file is intentionally not valid Python: the analyzer must report a parse
# error instead of crashing or claiming the file is clean.
def broken(request:
    os.system("ls " + request.args["x"])
