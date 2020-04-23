{
    "type": "global",
	"name": "dead",
	"instructions": [
		"find-bytes/or DE AD 12 34",
		"offset 4",
		"verify-bytes/or 00 00 00 05",
		"add-offset-range 0 1000 4",
		"verify-bytes 01 05 0b"
	]
}