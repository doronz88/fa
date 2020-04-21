def run(segments, manner, manner_args, addresses, args, **kwargs):
    args = eval(args)
    return [ea for ea in addresses if ea % args == 0]
