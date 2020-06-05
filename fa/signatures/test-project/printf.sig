{
    "type": "function",
	"name": "printf",
	"instructions": [
		find-str --or 'printf' --null-terminated
		xref
		print
		function-start
		single 0
		set-type 'void printf(const char *fmt, ...)'
	]
}
