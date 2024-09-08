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
    assert symbols['test_symdiff_ab'] == 4
    assert 'test_symdiff_bc' not in symbols
    assert symbols['test_symdiff_bcd'] == 8

    # test for branches
    assert 'test_is_single_false1' in symbols
    assert 'test_is_single_true1' not in symbols

    assert 'test_is_single_false2' not in symbols
    assert 'test_is_single_true2' in symbols

    assert 'test_else3' not in symbols
    assert 'test_if3' in symbols
