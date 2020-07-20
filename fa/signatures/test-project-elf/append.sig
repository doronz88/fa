{
    "type": "function",
	"name": "eloop_twice",
	"instructions": [
		"arm-find-all 'loop: b loop'"
		append arm-find-all 'loop: b loop'
		single 1
		set-name eloop_twice
	]
}
