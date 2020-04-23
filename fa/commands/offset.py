def run(segments, manners, addresses, args, **kwargs):
    return [ea + eval(args) for ea in addresses]
