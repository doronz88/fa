from fa import utils, context

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('verify-operand',
                                   description='verifies the given '
                                               'opcode\'s operands')
    p.add_argument('name')
    p.add_argument('--op0')
    p.add_argument('--op1')
    p.add_argument('--op2')
    return p


@context.ida_context
@utils.yield_unique
def verify_operand(addresses, mnem, op0=None, op1=None, op2=None):
    for address in addresses:
        current_mnem = idc.print_insn_mnem(address).lower()
        if current_mnem == mnem:
            if not op0 and not op1 and not op2:
                yield address
                continue

            regs_description = []

            if op0:
                regs_description.append((0, op0))
            if op1:
                regs_description.append((1, op1))
            if op2:
                regs_description.append((2, op2))

            for description in regs_description:
                index, values = description
                if idc.get_operand_value(address, index) not in values:
                    break
            else:
                yield address


def run(segments, args, addresses, interpreter=None, **kwargs):
    op0 = [int(i) for i in args.op0.split(',')] if args.op0 else None
    op1 = [int(i) for i in args.op1.split(',')] if args.op1 else None
    op2 = [int(i) for i in args.op2.split(',')] if args.op2 else None
    return list(verify_operand(addresses,
                               args.name,
                               op0=op0,
                               op1=op1,
                               op2=op2))
