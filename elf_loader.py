import click
from elftools.elf import elffile

from fa import fainterp


class ElfLoader(fainterp.FaInterp):
    def __init__(self):
        super(ElfLoader, self).__init__()
        self._elf = None

    def reload_segments(self):
        pass

    def set_input(self, input_):
        self._elf = elffile.ELFFile(input_)
        self.endianity = '<' if self._elf.little_endian else '>'

        self._segments = {}
        for s in self._elf.iter_segments():
            if s.header['p_type'] != 'PT_LOAD':
                continue
            self.segments[s.header['p_vaddr']] = s.data()

    @property
    def segments(self):
        return self._segments


@click.command()
@click.argument('elf_file', type=click.File('rb'))
@click.argument('signatures_root')
@click.argument('project')
def main(elf_file, signatures_root, project):
    interp = ElfLoader()
    interp.set_input(elf_file)
    interp.set_signatures_root(signatures_root)
    interp.set_project(project)

    for k, v in interp.symbols().items():
        if isinstance(v, list) or isinstance(v, set):
            if len(v) > 1:
                print('# {} multiple matches'.format(k))
                continue
            v = v.pop()
        print('{} = 0x{:x};'.format(k, v))


if __name__ == '__main__':
    main()
