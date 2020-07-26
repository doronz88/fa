from fa import utils, fa_types


def get_parser():
    p = utils.ArgumentParserNoExit('set-struct-member',
                                   description='add a struct member')
    p.add_argument('struct_name')
    p.add_argument('member_name')
    p.add_argument('member_type')
    return p


def set_struct_member(addresses, struct_name, member_name, member_type):
    for ea in addresses:
        enum = fa_types.FaStruct(struct_name)
        enum.add_field(member_name, member_type, offset=ea)
        enum.update_idb(delete_existing_members=False)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_struct_member(addresses, args.struct_name, args.member_name,
                             args.member_type)
