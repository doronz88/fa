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

        goto-ref --data
        set-name test_verify_goto_ref

        locate test_verify_operand
        set-name test_locate

        clear

        find_immediate 0x11223344
        set-name test_find_immediate
	]
}
