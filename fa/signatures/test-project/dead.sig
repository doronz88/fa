{
    "type": "global",
	"name": "dead",
	"instructions": [
		"find-bytes --or 'DE AD 12 34'",
		"offset 4",
		"verify-bytes '00 00 00 05'",
		"verify-bytes --until 1 '01 05 0b'"
	]
}