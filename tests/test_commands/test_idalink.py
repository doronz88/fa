from idalink import IDALink
import pytest

import sys
import importlib


class ImportInterceptor(object):
    def __init__(self, package_permissions):
        self.package_permissions = package_permissions

    def find_module(self, fullname, path=None):
        last = fullname.split('.')[-1]
        if last in dir(ida_namespace):
            return self
        if fullname in self.package_permissions:
            if self.package_permissions[fullname]:
                return self
            else:
                raise ImportError("Package import was not allowed")

    def load_module(self, fullname):
        last = fullname.split('.')[-1]
        if last in dir(ida_namespace):
            return getattr(ida_namespace, last)
        sys.meta_path = [x for x in sys.meta_path[1:] if x is not self]
        module = importlib.import_module(fullname)
        sys.meta_path = [self] + sys.meta_path
        return module


sys.meta_path.append(ImportInterceptor({'textwrap': True, 'Pathlib': False}))

ida_namespace = None


def test_ida_symbols(ida, sample_elf):
    sample_elf.close()

    if sys.version[0] == '3':
        pytest.skip('not supported for python3')

    global ida_namespace
    if None in (ida, ):
        pytest.skip("--ida param must be passed for this test")

    with IDALink(ida, sample_elf.name) as s:
        ida_namespace = s

        from fa import utils, context

        # hack to fix imports
        # flake8: noqa
        reload(utils)
        reload(context)

        s.ida_bytes.del_items(0x1240)
        s.ida_funcs.add_func(0x1248)
        s.ida_auto.auto_wait()

        from fa import ida_plugin
        fa_instance = ida_plugin.IdaLoader()
        fa_instance.set_input('ida')
        fa_instance.set_project('test-project-ida')
        symbols = fa_instance.symbols()

        for k, v in symbols.items():
            if isinstance(v, list) or isinstance(v, set):
                assert len(v) == 1
                symbols[k] = v.pop()

        consts = fa_instance.get_consts()

        # from test-basic
        assert symbols['test_add'] == 80
        assert symbols['test_pos_offset'] == 81
        assert symbols['test_neg_offset'] == 80
        assert symbols['test_add_offset_range'] == 100
        assert symbols['test_load'] == 80
        assert symbols['test_align'] == 84
        assert symbols['test_most_common'] == 2
        assert symbols['test_sort'] == 3
        assert symbols['test_verify_single_success'] == 1
        assert 'test_verify_single_fail' not in symbols
        assert symbols['test_run'] == 67
        assert symbols['test_alias'] == 0x123c
        assert symbols['test_keystone_find_opcodes'] == 0x123c
        assert symbols['test_keystone_verify_opcodes'] == 0x123c
        assert symbols['test_find_bytes'] == 0x1240
        assert symbols['test_find_str'] == 0x1242
        assert symbols['test_find'] == 76
        assert symbols['test_intersect_ab'] == 2
        assert 'test_intersect_abc' not in symbols

        # test for branches
        assert 'test_is_single_false1' in symbols
        assert 'test_is_single_true1' not in symbols

        assert 'test_is_single_false2' not in symbols
        assert 'test_is_single_true2' in symbols

        # from test-ida-context
        assert symbols['test_find_bytes_ida'] == 0x1240
        assert symbols['test_xref'] == 0x125c
        assert symbols['test_function_start'] == 0x1248
        assert symbols['test_function_end'] == 0x125c
        assert symbols['test_function_lines'] == 0x1248
        assert symbols['test_verify_operand'] == 0x1250
        assert symbols['test_verify_ref_no_name'] == 0x1250
        assert symbols['test_verify_goto_ref'] == 0x125c
        assert symbols['test_verify_ref_name'] == 0x1250
        assert symbols['test_locate'] == symbols['test_function_lines']
        assert symbols['test_find_immediate'] == 0x1240
        assert symbols['test_find_immediate'] == 0x1240
        assert symbols['test_operand'] == 1
        assert symbols['test_argument'] == 0x00001250
        assert 'test_branch1_false' not in symbols
        assert 'test_branch1_true' in symbols
