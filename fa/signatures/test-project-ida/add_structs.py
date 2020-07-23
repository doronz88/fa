from fa import fa_types


def run(interpreter):
    fa_types.add_const('CONST7', 7)
    fa_types.add_const('CONST8', 8)

    foo_e = fa_types.FaEnum('foo_e')
    foo_e.add_value('val2', 2)
    foo_e.add_value('val1', 1)
    foo_e.update_idb()

    special_struct_t = fa_types.FaStruct('special_struct_t')
    special_struct_t.add_field('member1', 'const char *')
    special_struct_t.add_field('member2', 'const char *', offset=0x20)
    special_struct_t.add_field('member3', 'char', offset=0x60)
    special_struct_t.add_field('member4', 'char', offset=0x61)
    special_struct_t.add_field('member5', 'const char *', offset=0x80)
    special_struct_t.update_idb()
