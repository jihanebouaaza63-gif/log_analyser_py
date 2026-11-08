import re


def extract_from_row(row):
    pattern = re.compile(
        r"(\w{3}\s + d{2}\s\+ (\d{2}:\d{2}:\d{2}) .+:\s(\w+)"
    )
    match = re.search(pattern, row)
    if match:
        print(
            f"month: {match.group(1)}\n,day: {match.group(2)}\n,"
            f"time: {match.group(3)}\n",
            f"message: {match.group(4)}\n   ",
        )


"""def extract():
    rows = raw.toRows('./data')

    for row in rows:
        pass
"""