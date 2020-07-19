{
    "type": "code-somewhere",
	"name": "ref_test",
	"instructions": [
		find-bytes '11 22 33 44'
		xref
		function-start
		arm-verify 'push {r4-r7, lr}'
		verify-single
		add-offset-range 0 20 4
		verify-operand bl
		single 0

		goto-ref --code
		offset 12
		verify-bytes 11223344
		stop-if-empty

		xref
		verify-operand ldr
		set-name ldr_ref
	]
}
