{
    "type": "global",
	"name": "dead",
	"instructions": [
		"find-bytes --or 'DE AD 12 34'",
		"offset 4",
		"verify-bytes '00 00 00 05'"
	]
}