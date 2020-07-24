{
    "type": "function",
	"name": "test",
	"instructions": [
	    find-bytes-ida 11223344
	    set-name test_find_bytes_ida

		xref
		set-name test_xref

        function-start
        set-name test_function_start
        checkpoint func

        function-end
        set-name test_function_end

        back-to-checkpoint func
        offset 10
        function-lines
        single 0
        set-name test_function_lines

        function-lines
        verify-operand ldr --op0 0
        set-name test_verify_operand
        checkpoint ref

        verify-ref --code --data
        set-name test_verify_ref_no_name

        goto-ref --data
        set-name test_verify_goto_ref

        back-to-checkpoint ref
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
	]
}
