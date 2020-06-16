{
    "type": "global",
	"name": "magic",
	"instructions": [
		find-bytes --or '11 22 33 44'
		unique
		checkpoint 11223344

		# verify the advance works
		offset 4
		verify-bytes '55 66 77 88'
		stop-if-empty
		checkpoint 55667788

		# verify negative advance works
		offset -4
		verify-bytes '11 22 33 44'
		stop-if-empty

		# verify checkpoint works
		back-to-checkpoint 55667788
		verify-bytes '55 66 77 88'
		stop-if-empty

		back-to-checkpoint 11223344
		verify-bytes '11 22 33 44'
		stop-if-empty

		# verify back command
		back 3
		verify-bytes '55 66 77 88'
		stop-if-empty

        # return the correct symbol
		back-to-checkpoint 11223344

		set-name magic
	]
}
