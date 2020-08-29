{
	"name": "test",
	"instructions": [
	    add 80
	    set-name test_add
	    store 80

	    offset 1
	    set-name test_pos_offset

	    offset -1
	    set-name test_neg_offset

	    add-offset-range 0 21 4
	    single -1
	    set-name test_add_offset_range

	    clear
	    load 80
	    set-name test_load

	    offset 1
	    align 4
	    set-name test_align

	    clear

	    add 1
	    add 2
	    add 3
	    add 2
	    most-common
	    set-name test_most_common

	    clear

	    add 1
	    add 2
	    add 3
	    add 2
	    sort
	    single -1
	    set-name test_sort

	    clear

	    add 1
	    add 1
	    verify-single
	    set-name test_verify_single_fail

	    clear

	    add 1
	    verify-single
	    set-name test_verify_single_success

	    clear

	    run test_dep.dep

	    clear

		arm-find-all 'loop: b loop'
		set-name test_alias
		set-name test_keystone_find_opcodes

		arm-verify 'loop: b loop'
		set-name test_keystone_verify_opcodes

		clear

		find-bytes 11223344
		set-name test_find_bytes

		verify-bytes 11223344
		set-name test_verify_bytes

        clear

        find-str '3DUfw'
        set-name test_find_str

        clear

        find test_find

        clear

        add 1
        add 2
        add 3

        store a

        clear

        add 2
        add 8
        add 12

        store b

        clear

        store c

        intersect a b
        set-name test_intersect_ab

        intersect a b c
        set-name test_intersect_abc

        clear

        add 1
        add 2

        verify-single
        store is_single1
        python-if is_single1 is_single_label1
            add 1
            set-name test_is_single_false1
            b end1

        label is_single_label1
            set-name test_is_single_true1

        label end1

        clear

        add 1

        verify-single
        store is_single2

        python-if is_single2 is_single_label2
        set-name test_is_single_false2
        b end2

        label is_single_label2
        set-name test_is_single_true2

        label end2

        clear

        add 1

        if 'verify-single' is_single_label3

        clear
        add 1
        set-name test_else3
        b end3

        label is_single_label3

        clear
        add 1
        set-name test_if3

        label end3

	]
}
