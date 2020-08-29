#!/usr/bin/python
import os
import shutil

shutil.copyfile(os.path.join(os.path.dirname(__file__),
                             'pre-commit'),
                os.path.join(
                    os.path.dirname(
                        os.path.dirname(os.path.dirname(__file__))),
                    '.git', 'hooks', 'pre-commit'))
