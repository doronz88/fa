from fa import fa_types


def run(**kwargs):
    fa_types.add_const('CONST7', 7)
    fa_types.add_const('CONST8', 8)

    foo_e = fa_types.FaEnum('foo_e')
    foo_e.add_value('val2', 2)
    foo_e.add_value('val1', 1)
    foo_e.update_idb()

    special_struct_t = fa_types.FaStruct('special_struct_t')
    special_struct_t.add_field('member1', 'const char *', size=4)
    special_struct_t.add_field('member2', 'const char *', size=4, offset=0x20)
    special_struct_t.update_idb()
