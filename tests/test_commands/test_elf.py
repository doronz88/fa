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

    assert symbols['test_add'] == 80
    assert symbols['test_pos_offset'] == 81
    assert symbols['test_neg_offset'] == 80
    assert symbols['test_add_offset_range'] == 100
    assert symbols['test_back_to_checkpoint'] == 80
    assert symbols['test_align'] == 84
    assert symbols['test_most_common'] == 2
    assert symbols['test_sort'] == 3
    assert symbols['test_verify_single_success'] == 1
    assert 'test_verify_single_fail' not in symbols
    assert symbols['test_run'] == 67
    assert symbols['test_alias'] == 0x123c
    assert symbols['test_keystone_find_opcodes'] == 0x123c
    assert symbols['test_keystone_verify_opcodes'] == 0x123c
    assert symbols['test_append'] == 2
    assert symbols['test_find_bytes'] == 0x1240
    assert symbols['test_find_str'] == 0x1242
    assert symbols['test_find'] == 76
    assert symbols['test_or_80'] == 80
    assert symbols['test_or_81'] == 81
    assert symbols['test_and_80'] == 80
    assert 'test_ond_81' not in symbols
    assert symbols['test_intersect_ab'] == 2
    assert 'test_intersect_abc' not in symbols
