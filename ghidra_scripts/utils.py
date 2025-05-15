import json


def read_json(filename):
    text = open(filename).read()
    return json.loads(text)
