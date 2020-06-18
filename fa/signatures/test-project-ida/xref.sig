{
    "type": "function",
	"name": "main",
	"instructions": [
		find-bytes --or '11 22 33 44'
		xref
		function-start
		print
		arm-verify 'push {r4-r7, lr}'
		unique
		set-name main
        set-type 'void main(void)'
	]
}
