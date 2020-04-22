def run(segments, manners, addresses, args, **kwargs):
    args = eval(args)
    return [ea for ea in addresses if ea % args == 0]
