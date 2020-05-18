from fa.commands.find_bytes import find_bytes
from fa.commands.set_type import set_type
from fa.commands import utils


def run():
    utils.verify_ida()
    result = list(find_bytes('de ad 12 34'))

    dead_t = utils.FaStruct('dead_t')
    dead_t.add_field('magic', 'unsigned int', 4)
    dead_t.update_idb()

    set_type(result[0], 'dead_t')

    utils.add_const('CYBER', 0x1337)

    return {'dead2': result[0]}
