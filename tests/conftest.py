import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--ida", action="store", default=None, help="IDA binary"
    )
    parser.addoption(
        "--idb", action="store", default=None, help="IDB file"
    )
    parser.addoption(
        "--elf", action="store", default=None, help="ELF file"
    )


@pytest.fixture
def ida(request):
    return request.config.getoption("--ida")


@pytest.fixture
def idb(request):
    return request.config.getoption("--idb")


@pytest.fixture
def elf(request):
    return request.config.getoption("--elf")
