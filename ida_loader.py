from fa.fa import IDA_MODULE, FA

if __name__ == '__main__':
    if IDA_MODULE:
        FA.log('''---------------------------------
FA Loaded successfully

Quick usage:
    fa.set_project(project_name) # select project name
    print(fa.list_projects()) # prints available projects
    print(fa.find(symbol_name)) # searches for the specific symbol
---------------------------------''')
        fa = FA()
        fa.set_project('test-project')
        fa.set_input('ida')

        for s in ('something1', 'something2', 's3', 's4'):
            fa.log(s)
            for ea in fa.find(s):
                fa.log('retval: ' + hex(ea))