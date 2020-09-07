import binascii
import re
import traceback
from collections import namedtuple
import subprocess
import tempfile
import sys
import os

sys.path.append('.')  # noqa: E402

import hjson
import click

from ida_kernwin import Form
import ida_kernwin
import ida_typeinf
import ida_bytes
import idautils
import ida_pro
import idaapi
import idc

from fa import fainterp, fa_types

# Filename for the temporary created signature
TEMP_SIG_FILENAME = os.path.join(tempfile.gettempdir(), 'fa_tmp_sig.sig')

# IDA fa plugin filename
PLUGIN_FILENAME = 'fa_ida_plugin.py'


def open_file(filename):
    """
    Attempt to open the given filename by OS' default editor
    :param filename: filename to open
    :return: None
    """
    if sys.platform == "win32":
        try:
            os.startfile(filename)
        except Exception as error_code:
            if error_code[0] == 1155:
                os.spawnl(os.P_NOWAIT,
                          os.path.join(os.environ['WINDIR'],
                                       'system32', 'Rundll32.exe'),
                          'Rundll32.exe SHELL32.DLL, OpenAs_RunDLL {}'
                          .format(filename))
            else:
                print("other error")
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, filename])


class IdaLoader(fainterp.FaInterp):
    """
    IDA loader
    Includes improved GUI interaction for accessing the interpreter
    functionality.
    """

    def __init__(self):
        super(IdaLoader, self).__init__()
        self._create_template_symbol = eval(self.config_get(
            'global',
            'create_symbol_template',
            'False'
        ))

    def set_symbol_template(self, status):
        """
        Should the create-temp-signature feature attempt to create a default
        signature by predefined template?
        :param status: new boolean setting
        :return: None
        """
        self._create_template_symbol = status
        self.config_set('global', 'create_symbol_template', str(status))

    def create_symbol(self):
        """
        Create a temporary symbol signature from the current function on the
        IDA screen.
        """
        self.log('creating temporary signature')

        current_ea = idc.get_screen_ea()

        signature = {
            'name': idc.get_func_name(current_ea),
            'instructions': []
        }

        if self._create_template_symbol:
            find_bytes_ida = "find-bytes-ida '"

            for ea in idautils.FuncItems(current_ea):
                mnem = idc.print_insn_mnem(ea).lower()
                opcode_size = idc.get_item_size(ea)

                # ppc
                if mnem.startswith('b') or mnem in ('lis', 'lwz', 'addi'):
                    # relative opcodes
                    find_bytes_ida += '?? ' * opcode_size
                    continue

                # arm
                if mnem.startswith('b') or mnem in ('ldr', 'str'):
                    # relative opcodes
                    find_bytes_ida += '?? ' * opcode_size
                    continue

                opcode = binascii.hexlify(idc.get_bytes(ea, opcode_size))
                formatted_hex = ' '.join(opcode[i:i + 2] for i in
                                         range(0, len(opcode), 2))
                find_bytes_ida += formatted_hex + ' '

            find_bytes_ida += "'"

            signature['instructions'].append(find_bytes_ida)
            signature['instructions'].append('function-start')
            signature['instructions'].append('set-name "{}"'.format(
                idc.get_func_name(current_ea)))

        with open(TEMP_SIG_FILENAME, 'w') as f:
            hjson.dump(signature, f, indent=4)

        self.log('Signature created at {}'.format(TEMP_SIG_FILENAME))
        return TEMP_SIG_FILENAME

    def extended_create_symbol(self):
        """
        Creates a temporary symbol of the currently active function
        and open it using OS default editor
        :return: None
        """
        filename = self.create_symbol()
        open_file(filename)

    def find_symbol(self):
        """
        Find the last create symbol signature.
        :return: None
        """
        with open(TEMP_SIG_FILENAME) as f:
            sig = hjson.load(f)

        results = self.find_from_sig_json(sig, decremental=False)

        for address in results:
            self.log('Search result: 0x{:x}'.format(address))
        self.log('Search done')

        if len(results) == 1:
            # if remote sig has a proper name, but current one is not
            ida_kernwin.jumpto(results[0])

    def verify_project(self):
        """
        Verify a valid project is currently active.
        Show IDA warning if not.
        :return: None
        """
        try:
            super(IdaLoader, self).verify_project()
        except IOError as e:
            ida_kernwin.warning(e.message)
            raise e

    def prompt_save_signature(self):
        """
        Save last-created-temp-signature if user agrees to in IDA prompt
        :return: None
        """
        self.verify_project()

        if ida_kernwin.ask_yn(1, 'Are you sure you want '
                                 'to save this signature?') != 1:
            return

        self.save_signature(TEMP_SIG_FILENAME)

    def find(self, symbol_name, use_cache=False):
        """
        Find symbol by name (as specified in SIG file)
        Show an IDA waitbox while doing so
        :param symbol_name: symbol name
        :return: output address list
        """
        ida_kernwin.replace_wait_box('Searching symbol: \'{}\'...'
                                     .format(symbol_name))
        return super(IdaLoader, self).find(symbol_name, use_cache=use_cache)

    def get_python_symbols(self, file_name=None):
        """
        Run all python scripts inside the currently active project.
        Show an IDA waitbox while doing so
        :param file_name: filter a specific filename to execute
        :return: dictionary of all found symbols
        """
        ida_kernwin.replace_wait_box('Running python scripts...')
        return super(IdaLoader, self).get_python_symbols(file_name=file_name)

    @staticmethod
    def extract_all_user_names(filename=None):
        """
        Get all user-named labels inside IDA. Also prints into output window.
        :return: dictionary of all user named labels: label_name -> ea
        """
        results = {}
        output = ''

        for ea, name in idautils.Names():
            if ida_kernwin.user_cancelled():
                return results

            if '_' in name:
                if name.split('_')[0] in ('def', 'sub', 'loc', 'jpt', 'j',
                                          'nullsub'):
                    continue
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.has_user_name(flags):
                results[name] = ea
                output += '{} = 0x{:08x};\n'.format(name, ea)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(output)

        return results

    def set_const(self, name, value):
        super(IdaLoader, self).set_const(name, value)
        fa_types.add_const(name, value)

    def set_symbol(self, symbol_name, value):
        super(IdaLoader, self).set_symbol(symbol_name, value)
        idc.set_name(value, symbol_name, idc.SN_CHECK)

    def symbols(self, output_file_path=None):
        """
        Run find for all SIG files in currently active project.
        Show an IDA waitbox while doing so
        :param output_file_path: optional, save found symbols into output file
        :return: dictionary of found symbols
        """
        self.verify_project()
        results = {}

        try:
            ida_kernwin.show_wait_box('Searching...')
            results = super(IdaLoader, self).symbols()

            ida_kernwin.replace_wait_box('Extracting...')
            ida_symbols = IdaLoader.extract_all_user_names(output_file_path)

            results.update(ida_symbols)

        except Exception as e:
            traceback.print_exc()
        finally:
            ida_kernwin.hide_wait_box()

        return results

    def export(self):
        """
        Show an export dialog to export symbols and header file for given
        IDB.
        :return: None
        """
        class ExportForm(Form):
            def __init__(self):
                description = '''
                <h2>Export</h2>

                Select a directory to export IDB data into.
                '''

                Form.__init__(self,
                              r"""BUTTON YES* Save
                              Export
                              {StringLabel}
                              <#Symbols#Symbols filename:{iSymbolsFilename}>
                              <#C Header#C Header filename:{iHeaderFilename}>
                              <#ifdef_macro#ifdef'ed:{iIfdef}>
                              <#Select dir#Browse for dir:{iDir}>
                              """, {
                                  'iDir': Form.DirInput(),
                                  'StringLabel':
                                      Form.StringLabel(description,
                                                       tp=Form.FT_HTML_LABEL),
                                  'iSymbolsFilename': Form.StringInput(
                                      value='symbols.txt'),
                                  'iHeaderFilename': Form.StringInput(
                                      value='fa_structs.h'),
                                  'iIfdef': Form.StringInput(
                                      value='FA_STRUCTS_H'),
                              })
                self.__n = 0

            def OnFormChange(self, fid):
                return 1

        form = ExportForm()
        form, args = form.Compile()
        ok = form.Execute()
        if ok == 1:
            # save symbols
            symbols_filename = os.path.join(form.iDir.value,
                                            form.iSymbolsFilename.value)
            with open(symbols_filename, 'w') as f:
                results = IdaLoader.extract_all_user_names(None)
                for k, v in results.items():
                    f.write('{} = 0x{:08x};\n'.format(k, v))

            # save c header
            idati = ida_typeinf.get_idati()
            c_header_filename = os.path.join(form.iDir.value,
                                             form.iHeaderFilename.value)

            consts_ordinal = None
            ordinals = []
            for ordinal in range(1, ida_typeinf.get_ordinal_qty(idati) + 1):
                ti = ida_typeinf.tinfo_t()
                if ti.get_numbered_type(idati, ordinal):
                    if ti.get_type_name() == 'FA_CONSTS':
                        # convert into macro definitions
                        consts_ordinal = ordinal
                    elif ti.get_type_name() in ('__va_list_tag',
                                                'va_list'):
                        continue
                    elif '$' in ti.get_type_name():
                        # skip deleted types
                        continue
                    else:
                        ordinals.append(str(ordinal))

            with open(c_header_filename, 'w') as f:
                ifdef_name = form.iIfdef.value.strip()

                if len(ifdef_name) > 0:
                    f.write('#ifndef {ifdef_name}\n'
                            '#define {ifdef_name}\n\n'
                            .format(ifdef_name=ifdef_name))

                if consts_ordinal is not None:
                    consts = re.findall('\s*(.+?) = (.+?),',
                                        idc.print_decls(
                                            str(consts_ordinal), 0))
                    for k, v in consts:
                        f.write('#define {} ({})\n'.format(k, v))

                    # ida exports using this type
                    f.write('#define _BYTE char\n')
                    f.write('\n')

                structs_buf = idc.print_decls(','.join(ordinals),
                                              idc.PDF_DEF_BASE)

                for struct_type, struct_name in re.findall(
                        r'(struct|enum) .*?([a-zA-Z0-9_\-]+?)\s+\{',
                        structs_buf):
                    f.write(
                        'typedef {struct_type} {struct_name} {struct_name};\n'
                        .format(struct_type=struct_type,
                                struct_name=struct_name))

                structs_buf = structs_buf.replace('__fastcall', '')
                f.write('\n')
                f.write(structs_buf)
                f.write('\n')

                if len(ifdef_name) > 0:
                    f.write('#endif // {ifdef_name}\n'
                            .format(ifdef_name=ifdef_name))

        form.Free()

    def set_input(self, input_):
        """
        Mock for change_input. Just reload current loaded data settings.
        :param input_: doesn't matter
        :return: None
        """
        self.endianity = '>' if idaapi.get_inf_structure().is_be() else '<'
        self._input = input_
        self.reload_segments()

    def reload_segments(self):
        """
        memory searches will use IDA's API instead
        which is much faster so this is just a stub.
        :return: None
        """
        return

    def interactive_settings(self):
        """
        Show settings dialog
        :return: None
        """
        class SettingsForm(Form):
            def __init__(self, signatures_root, use_template):
                description = '''
                <h2>Settings</h2>
                <div>
                Here you can change global FA settings.
                </div>
                <div>
                    <a href="https://github.com/doronz88/fa">
                    For more info</a>
                </div>
                '''

                Form.__init__(self,
                              r"""BUTTON YES* Save
                              FA Settings
                              {{FormChangeCb}}
                              {{StringLabel}}
                              <Signatures root :{{signaturesRoot}}>
                              <Temp signature generation :{{signatureGeneration}}>
                              """.format(signatures_root), {
                                  'FormChangeCb':
                                      Form.FormChangeCb(self.OnFormChange),
                                  'signaturesRoot':
                                      Form.DirInput(value=signatures_root),
                                  'StringLabel':
                                      Form.StringLabel(description,
                                                       tp=Form.FT_HTML_LABEL),
                                  'signatureGeneration':
                                      Form.DropdownListControl(
                                          items=['Default',
                                                 'Using function bytes'],
                                          readonly=True,
                                          selval=use_template),
                              })
                self.__n = 0

            def OnFormChange(self, fid):
                return 1

        f = SettingsForm(self._signatures_root, self._create_template_symbol)
        f, args = f.Compile()
        ok = f.Execute()
        if ok == 1:
            self.set_signatures_root(f.signaturesRoot.value, save=True)
            self.set_symbol_template(f.signatureGeneration.value == 1)
        f.Free()

    def interactive_set_project(self):
        """
        Show set-project dialog
        :return: None
        """
        class SetProjectForm(Form):
            def __init__(self, signatures_root, projects, current):
                description = '''
                <h2>Project Selector</h2>
                <div>
                Select project you wish to work on from your
                signatures root:
                </div>
                <div><pre>{}</pre></div>
                <div><i>(Note: You may change this in config.ini)</i></div>
                <div>
                    <a href="https://github.com/doronz88/fa#projects">
                    For more info</a>
                </div>
                '''.format(signatures_root)

                Form.__init__(self,
                              r"""BUTTON YES* OK
                              FA Project Select
                              {{FormChangeCb}}
                              {{StringLabel}}
                              <Set Project :{{cbReadonly}}>
                              """.format(signatures_root), {
                                  'FormChangeCb':
                                      Form.FormChangeCb(self.OnFormChange),
                                  'cbReadonly':
                                      Form.DropdownListControl(
                                          items=projects,
                                          readonly=True,
                                          selval=projects.index(current)
                                          if current in projects else 0),
                                  'StringLabel':
                                      Form.StringLabel(description,
                                                       tp=Form.FT_HTML_LABEL),
                              })
                self.__n = 0

            def OnFormChange(self, fid):
                return 1

        projects = self.list_projects()
        f = SetProjectForm(self._signatures_root, projects, self._project)
        f, args = f.Compile()
        ok = f.Execute()
        if ok == 1:
            self.set_project(projects[f.cbReadonly.value])
        f.Free()


fa_instance = None

Action = namedtuple('action', 'name icon_filename handler label hotkey')


def add_action(action):
    """
    Add an ida-action
    :param action: action given as the `Action` namedtuple
    :return: None
    """
    class Handler(ida_kernwin.action_handler_t):
        def __init__(self):
            ida_kernwin.action_handler_t.__init__(self)

        def activate(self, ctx):
            action.handler()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

    act_icon = -1
    if action.icon_filename:
        icon_full_filename = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'res', 'icons', action.icon_filename)
        with open(icon_full_filename, 'rb') as f:
            icon_data = f.read()
        act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")

    act_name = action.name

    ida_kernwin.unregister_action(act_name)
    if ida_kernwin.register_action(ida_kernwin.action_desc_t(
            act_name,  # Name. Acts as an ID. Must be unique.
            action.label,  # Label. That's what users see.
            Handler(),  # Handler. Called when activated, and for updating
            action.hotkey,  # Shortcut (optional)
            None,  # Tooltip (optional)
            act_icon)):  # Icon ID (optional)

        # Insert the action in the menu
        if not ida_kernwin.attach_action_to_menu(
                "FA/", act_name, ida_kernwin.SETMENU_APP):
            print("Failed attaching to menu.")

        # Insert the action in a toolbar
        if not ida_kernwin.attach_action_to_toolbar("fa", act_name):
            print("Failed attaching to toolbar.")

        class Hooks(ida_kernwin.UI_Hooks):
            def finish_populating_widget_popup(self, widget, popup):
                if ida_kernwin.get_widget_type(widget) == \
                        ida_kernwin.BWN_DISASM:
                    ida_kernwin.attach_action_to_popup(widget,
                                                       popup,
                                                       act_name,
                                                       None)

        hooks = Hooks()
        hooks.hook()


def load_ui():
    """
    Load FA's GUI buttons
    :return: None
    """
    actions = [
        Action(name='fa:settings',
               icon_filename='settings.png',
               handler=fa_instance.interactive_settings,
               label='Settings',
               hotkey=None),

        Action(name='fa:set-project',
               icon_filename='suitcase.png',
               handler=fa_instance.interactive_set_project,
               label='Set project...',
               hotkey='Ctrl+6'),

        Action(name='fa:symbols', icon_filename='find_all.png',
               handler=fa_instance.symbols,
               label='Find all project\'s symbols',
               hotkey='Ctrl+7'),

        Action(name='fa:export', icon_filename='export.png',
               handler=fa_instance.export,
               label='Export symbols',
               hotkey=None),

        Action(name='fa:extended-create-signature',
               icon_filename='create_sig.png',
               handler=fa_instance.extended_create_symbol,
               label='Create temp signature...',
               hotkey='Ctrl+8'),

        Action(name='fa:find-symbol',
               icon_filename='find.png',
               handler=fa_instance.find_symbol,
               label='Find last created temp signature',
               hotkey='Ctrl+9'),

        Action(name='fa:prompt-save',
               icon_filename='save.png',
               handler=fa_instance.prompt_save_signature,
               label='Save last created temp signature',
               hotkey='Ctrl+0'),
    ]

    # init toolbar
    ida_kernwin.delete_toolbar('fa')
    ida_kernwin.create_toolbar('fa', 'FA Toolbar')

    # init menu
    ida_kernwin.delete_menu('fa')
    ida_kernwin.create_menu('fa', 'FA')

    for action in actions:
        add_action(action)


def install():
    """
    Install FA ida plugin
    :return: None
    """
    fa_plugin_dir = os.path.join(
        idaapi.get_user_idadir(), 'plugins')

    if not os.path.exists(fa_plugin_dir):
        os.makedirs(fa_plugin_dir)

    fa_plugin_filename = os.path.join(fa_plugin_dir, PLUGIN_FILENAME)
    if os.path.exists(fa_plugin_filename):
        IdaLoader.log('already installed')
        return

    with open(fa_plugin_filename, 'w') as f:
        f.writelines("""from __future__ import print_function
try:
    from fa.ida_plugin import PLUGIN_ENTRY, FAIDAPlugIn
except ImportError:
    print("[WARN] Could not load FA plugin. "
          "FA Python package doesn\'t seem to be installed.")
""")

    idaapi.load_plugin(PLUGIN_FILENAME)

    IdaLoader.log('Successfully installed :)')


@click.command()
@click.argument('signatures_root', default='.')
@click.option('--project_name', default=None)
@click.option('--symbols-file', default=None)
def main(signatures_root, project_name, symbols_file=None):
    plugin_main(signatures_root, project_name, symbols_file)


def plugin_main(signatures_root, project_name, symbols_file=None):
    global fa_instance

    fa_instance = IdaLoader()
    fa_instance.set_input('ida')

    if project_name is not None:
        fa_instance.set_project(project_name)

    load_ui()

    IdaLoader.log('''    ---------------------------------
    FA Loaded successfully

    Quick usage:
    print(fa_instance.find(symbol_name)) # searches for the specific symbol
    fa_instance.get_python_symbols(filename=None) # run project's python
                                                    scripts (all or single)
    fa_instance.set_symbol_template(status) # enable/disable template temp
                                              signature
    fa_instance.symbols() # searches for the symbols in the current project
    ---------------------------------''')

    if symbols_file is not None:
        fa_instance.set_signatures_root(signatures_root)
        fa_instance.symbols(symbols_file)
        ida_pro.qexit(0)

    # TODO: consider adding as autostart script
    # install()


try:
    class FAIDAPlugIn(idaapi.plugin_t):
        wanted_name = "FA"
        wanted_hotkey = "Shift-,"
        flags = 0
        comment = ""
        help = "Load FA in IDA Pro"

        def init(self):
            plugin_main('.', None, None)
            return idaapi.PLUGIN_KEEP

        def run(self, args):
            pass

        def term(self):
            pass
except TypeError:
    print('ignoring rpyc bug')


def PLUGIN_ENTRY():
    """
    Entry point for IDA plugins
    :return:
    """
    return FAIDAPlugIn()


if __name__ == '__main__':
    # Entry point for IDA in script mode (-S)
    main(standalone_mode=False, args=idc.ARGV[1:])
