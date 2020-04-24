{
    "type": "global",
	"name": "dead",
	"instructions": [
		"find-bytes/or DE AD 12 34",
		"offset 4",
		"verify-bytes/or 00 00 00 05",
		"verify-bytes/until 01 05 0b"
	]
}