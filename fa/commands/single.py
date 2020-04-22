def run(segments, manners, addresses, args, **kwargs):
    return [addresses.pop()] if len(addresses) >= 1 else []
