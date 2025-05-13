import base64

file = "data/discoverer2.txt"
text = open(file).read()
blob = bytearray()
for i, line in enumerate(text.splitlines()):
    if i == 0:
        continue
    if line.startswith('  '):
        break
    hex_symbols = line[10:57]
    bytes = [int(hex_str, 16) for hex_str in hex_symbols.split(' ')]
    blob.extend(bytes)
print(base64.standard_b64encode(blob).decode('utf-8'))
