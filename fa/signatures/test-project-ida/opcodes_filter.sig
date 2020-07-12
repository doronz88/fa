{
    "type": "code-somewhere",
	"name": "second_bl",
	"instructions": [
		find-bytes --or '11 22 33 44'
		offset 1
		align 4
		verify-bytes '55 66 77 88'
		offset -4
		xref
		function-start
		arm-verify 'push {r4-r7, lr}'
		unique
		add-offset-range 0 20 4
		verify-operand bl
		single 1
		set-name second_bl
	]
}
