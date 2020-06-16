import pytest
import elf_loader


def test_elf_symbols(sample_elf):
    if sample_elf is None:
        pytest.skip("--elf param must be passed for this test")
        return

    fa_instance = elf_loader.ElfLoader()
    fa_instance.set_input(sample_elf)

    fa_instance.set_project('test-project-elf')
    symbols = fa_instance.symbols()

    for k, v in symbols.items():
        assert len(v) == 1
        symbols[k] = v.pop()

    assert symbols['magic'] == 0x1240
