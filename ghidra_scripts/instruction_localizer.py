import os
import json
from utils import read_json

script_directory = os.path.dirname(os.path.realpath(__file__))
data_filepath = os.path.normpath(
    os.path.join(script_directory, "../data/offsets.json"))
location_offsets = read_json(data_filepath)

functionManager = currentProgram.getFunctionManager()


def getFunctionContaining(offset):
    functionAddress = currentProgram.getImageBase().add(offset)
    return functionManager.getFunctionContaining(functionAddress)


function_offsets = {}
for location_offset in location_offsets:
    offset_num = int(location_offset[2:], 16)
    function = getFunctionContaining(offset_num)
    if not function:
        function_offsets[location_offset] = None
    else:
        function_address = int(function.getEntryPoint().subtract(
            currentProgram.getImageBase()))
        function_offset = hex(function_address)
        function_offsets[location_offset] = function_offset

print(json.dumps(function_offsets))
