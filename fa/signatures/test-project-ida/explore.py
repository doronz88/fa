TEMPLATE = '''
arm-find-all 'push {r4, r5, r6, r7, lr}'
make-function
'''


def run(**kwargs):
    interp = kwargs['interpreter']
    interp.find_from_instructions_list(TEMPLATE.splitlines())

    return {}
