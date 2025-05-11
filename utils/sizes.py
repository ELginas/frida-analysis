text = open('data/sizes.txt').read()
sizes = [line.split(' ')[0] for line in text.splitlines()]


def convert_size(text):
    num = text[:-1]
    multiplier = text[-1]
    multipliers = {'k': 1_000, 'M': 1_000_000}
    multiplier_num = multipliers[multiplier]
    return float(num) * multiplier_num


print(sizes)
size_nums = [convert_size(size) for size in sizes]

sum = 0
for size in size_nums:
    sum += size
print(sum)
