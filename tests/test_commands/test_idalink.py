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

        from fa import utils

        # hack to fix imports
        # flake8: noqa
        reload(utils)

        utils.verify_ida()
        s.ida_bytes.del_items(0x1240)
        s.ida_funcs.add_func(0x1248)
        s.ida_auto.auto_wait()

        import ida_loader
        fa_instance = ida_loader.IdaLoader()
        fa_instance.set_input('ida')
        fa_instance.set_project('test-project-ida')
        symbols = fa_instance.symbols()

        for k, v in symbols.items():
            if isinstance(v, list) or isinstance(v, set):
                assert len(v) == 1
                symbols[k] = v.pop()

        assert symbols['magic'] == 0x1240
        assert symbols['eloop'] == 0x123c
        assert symbols['main'] == 0x1248
        assert symbols['ldr_ref'] == 0x1250
        assert symbols['second_bl'] == 0x1254
