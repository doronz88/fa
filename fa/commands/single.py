def run(segments, manner, manner_args, addresses, args, **kwargs):
    return [addresses.pop()] if len(addresses) >= 1 else []
