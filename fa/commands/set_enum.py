from fa import utils, fa_types


def get_parser():
    p = utils.ArgumentParserNoExit('set-enum',
                                   description='define an enum value')
    p.add_argument('enum_name')
    p.add_argument('enum_key')
    return p


def set_enum(addresses, enum_name, enum_key):
    for ea in addresses:
        enum = fa_types.FaEnum(enum_name)
        enum.add_value(enum_key, ea)
        enum.update_idb()
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_enum(addresses, args.enum_name, args.enum_key)
