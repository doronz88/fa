{
    "type": "function",
	"name": "main",
	"instructions": [
		find-bytes '11 22 33 44'
		xref
		function-start
		arm-verify 'push {r4-r7, lr}'
		make-comment 'function prolog'
        verify-segment .text
		verify-single
		set-name main
        set-type 'void main(void)'
	]
}
