{
	"name": "test",
	"instructions": [
	    find-bytes-ida 11223344
	    set-name test_find_bytes_ida

		xref
		set-name test_xref

        function-start
        set-name test_function_start
        store func

        function-end
        set-name test_function_end

        load func
        offset 10
        function-lines
        single 0
        set-name test_function_lines

        function-lines
        verify-operand ldr --op0 0
        set-name test_verify_operand
        store ref

        verify-ref --code --data
        set-name test_verify_ref_no_name

        goto-ref --data
        set-name test_verify_goto_ref

        load ref
        verify-ref --name test_verify_goto_ref --code --data
        set-name test_verify_ref_name

        locate test_function_lines
        set-name test_locate

        clear

        find_immediate 0x11223344
        set-name test_find_immediate

        clear

        add 4
        set-const TEST_CONST_VALUE_4
        set-enum TEST_ENUM_NAME TEST_ENUM_KEY1_VALUE_4

        clear

        add 6
        set-enum TEST_ENUM_NAME TEST_ENUM_KEY2_VALUE_6

        clear

        arm-find-all 'mov r0, 1'
        single 0
        operand 1
        set-name test_operand

        clear

        add 0
        set-struct-member test_struct_t test_member_offset_0 'unsigned int'

        offset 4
        set-struct-member test_struct_t test_member_offset_4 'unsigned int'

        clear

        arm-find-all 'mov r0, 1; bx lr'
        set-name funcy
        set-type 'int func(int)'
        xref
        sort
        single 1
        argument 0

        set-name test_argument

        clear

        arm-find-all 'mov r0, 1; bx lr'

        verify-operand mov --op0 0
        store tmp

        python-if tmp test_branch1
        set-name test_branch1_false

        label test_branch1
        set-name test_branch1_true
	]
}
