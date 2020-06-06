{
    "type": "function",
	"name": "printf",
	"instructions": [
		find-str --or 'printf' --null-terminated
		xref
		sort
		print
		function-start
		most-common
		max-xrefs
		single 0
		aligned 4
		make-code
		make-function
		set-name printf
		set-type 'void printf(const char *fmt, ...)'

        clear
		locate printf
		checkpoint printf
		back-to-checkpoint printf
		function-lines
		verify-operand bl
		goto-ref --code
		back 2
		offset 4
		offset -4

		locate printf
	]
}
