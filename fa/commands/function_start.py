from fa.commands import utils

try:
    import idc
    import idaapi
    import _idaapi
    import idautils
except ImportError:
    pass


def run(segments, manners, addresses, args, **kwargs):
    utils.verify_ida()
    return list(set([idc.GetFunctionAttr(ea, idc.FUNCATTR_START) for ea in addresses]))
