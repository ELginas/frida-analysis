import json
import os

script_directory = os.path.dirname(os.path.realpath(__file__))
data_filepath = os.path.normpath(
    os.path.join(script_directory, "../data/test.json"))
application_name = "btm"

functionManager = currentProgram.getFunctionManager()


def getFunctionAt(offset):
    functionAddress = currentProgram.getImageBase().add(offset)
    return functionManager.getFunctionAt(functionAddress)


def read_json(filename):
    text = open(filename).read()
    return json.loads(text)


data = read_json(data_filepath)
results = {}
for function_name in data["function_counts"][application_name]:
    if function_name.startswith("sub_"):
        hex_str = function_name[4:]
        offset = int(hex_str, 16)
        function = getFunctionAt(offset)
        signature = function.getSignature()
        results[hex(offset)] = str(signature)
    else:
        raise NotImplementedError
print(json.dumps(results, indent=2))
