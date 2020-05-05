from fa.commands import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('name')
    p.add_argument('--op0')
    p.add_argument('--op1')
    p.add_argument('--op2')
    return p


@utils.yield_unique
def verify_operand(addresses, name, op0=None, op1=None, op2=None):
    for address in addresses:
        if idc.print_insn_mnem(address) == name:
            if not (op0 and op1 and op2):
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


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    regs_op0 = args.regs_op0.split(',') if args.regs_op0 else None
    regs_op1 = args.regs_op1.split(',') if args.regs_op1 else None
    regs_op2 = args.regs_op2.split(',') if args.regs_op2 else None
    return list(verify_operand(addresses,
                               args.name,
                               op0=regs_op0,
                               op1=regs_op1,
                               op2=regs_op2))
