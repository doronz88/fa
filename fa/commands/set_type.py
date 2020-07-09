from fa import utils, fa_types, context

try:
    import idc
    import ida_auto
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('set-type',
                                   description='sets the type in '
                                               'the disassembler')
    p.add_argument('type_str')
    return p


def set_type_single(address, type_):
    if isinstance(type_, fa_types.FaStruct) or \
            isinstance(type_, fa_types.FaEnum):
        type_str = type_.get_name()
    else:
        type_str = type_

    idc.SetType(address, type_str)
    ida_auto.auto_wait()


@context.ida_context
def set_type(addresses, type_):
    for ea in addresses:
        set_type_single(ea, type_)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_type(addresses, args.type_str)
