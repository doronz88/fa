from collections import OrderedDict


def run(segments, manners, addresses, args, **kwargs):
    start = 0
    end = 0
    skip = 1

    if ' ' in args:
        start, args = args.split(' ', 1)
        start = eval(start)
        if ' ' in args:
            end, args = args.split(' ', 1)
            end = eval(end)
            if ' ' in args:
                skip, args = args.split(' ', 1)
                skip = eval(start)

    retval = []

    for ea in addresses:
        for i in range(start, end, skip):
            retval.append(ea + i)

    return list(OrderedDict.fromkeys(retval))
