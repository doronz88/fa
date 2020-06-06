import pytest
import elf_loader


def test_elf_symbols(elf):
    if elf is None:
        pytest.skip("--elf param must be passed for this test")
        return

    fa_instance = elf_loader.ElfLoader()
    with open(elf, 'rb') as elf:
        fa_instance.set_input(elf)

    fa_instance.set_project('test-project-elf')
    fa_instance.symbols()
