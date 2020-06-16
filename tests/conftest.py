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
def sample_elf(request):
    import tempfile
    from simpleelf.elf_builder import ElfBuilder
    from simpleelf import elf_consts

    with tempfile.NamedTemporaryFile() as f:
        e = ElfBuilder()
        e.set_endianity('>')
        e.set_machine(elf_consts.EM_ARM)

        from keystone import *

        # add a segment
        text_address = 0x1234

        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM | KS_MODE_BIG_ENDIAN)

        text_buffer = ks.asm('''
        ret_1:
            mov r0, #1
            bx lr
        eloop:
             b eloop
        data:
            .word 0x11223344
            .word 0x55667788
        ''', text_address)[0]
        text_buffer = bytearray(text_buffer)

        e.add_segment(text_address, text_buffer,
                      elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X)
        e.add_code_section('.text', text_address, len(text_buffer))
        f.write(e.build())
        yield f


@pytest.fixture
def ida(request):
    return request.config.getoption("--ida")


@pytest.fixture
def idb(request):
    return request.config.getoption("--idb")


@pytest.fixture
def elf(request):
    return request.config.getoption("--elf")
