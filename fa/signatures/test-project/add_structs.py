from fa.commands import utils


def run(**kwargs):
    utils.add_const('CONST7', 7)
    utils.add_const('CONST8', 8)

    foo_e = utils.FaEnum('foo_e')
    foo_e.add_value('val2', 2)
    foo_e.add_value('val1', 1)
    foo_e.update_idb()

    special_struct_t = utils.FaStruct('special_struct_t')
    special_struct_t.add_field('member1', 'const char *', size=4)
    special_struct_t.add_field('member2', 'const char *', size=4, offset=0x20)
    special_struct_t.update_idb()

    return {}
