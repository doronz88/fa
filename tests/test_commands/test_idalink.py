from idalink import IDALink
import pytest

import sys
import importlib


class ImportInterceptor(object):
    def __init__(self, package_permissions):
        self.package_permissions = package_permissions

    def find_module(self, fullname, path=None):
        if fullname in dir(ida_namespace):
            return self
        if fullname in self.package_permissions:
            if self.package_permissions[fullname]:
                return self
            else:
                raise ImportError("Package import was not allowed")

    def load_module(self, fullname):
        if fullname in dir(ida_namespace):
            return getattr(ida_namespace, fullname)
        sys.meta_path = [x for x in sys.meta_path[1:] if x is not self]
        module = importlib.import_module(fullname)
        sys.meta_path = [self] + sys.meta_path
        return module


if not hasattr(sys, 'frozen'):
    sys.meta_path = [ImportInterceptor({'textwrap': True,
                                        'Pathlib': False})] + sys.meta_path


ida_namespace = None


def test_ida_symbols(ida, idb):
    global ida_namespace
    if None in (ida, idb):
        pytest.skip("--ida and --idb params must be passed for this test")
    with IDALink(ida, idb) as s:
        ida_namespace = s
        import ida_loader
        fa_instance = ida_loader.IdaLoader()
        fa_instance.set_input('ida')
        fa_instance.set_project('test-project')
        fa_instance.symbols()
