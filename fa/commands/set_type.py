from fa.commands import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('set-type',
                                   description='sets the type in '
                                               'the disassembler')
    p.add_argument('type_str')
    return p


def set_type(address, type_):
    if isinstance(type_, utils.FaStruct) or \
            isinstance(type_, utils.FaEnum):
        type_str = type_.get_name()
    else:
        type_str = type_

    idc.SetType(address, type_str)
    idc.Wait()


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    for address in addresses:
        set_type(address, args.type_str)

    return addresses
