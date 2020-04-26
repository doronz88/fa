{
    "type": "global",
    "name": "opcodes-ppc",
	"instructions": [
		"ppc32-find-all 'mr %r12, %r1;'",
		"keystone-verify-opcodes --bele --until 4 KS_ARCH_PPC KS_MODE_PPC32 'mflr %r0'",
        "single"
	]
}


