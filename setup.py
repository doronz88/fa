from setuptools import setup

setup(
    name='fa',
    version='0.2.2',
    description='FA Plugin',
    author='DoronZ',
    author_email='doron88@gmail.com',
    url='https://github.com/doronz88/fa',
    packages=['fa', 'fa.commands'],
    package_dir={'fa': 'fa'},
    data_files=[(r'fa/res/icons', [r'fa/res/icons/create_sig.png',
                                   r'fa/res/icons/export.png',
                                   r'fa/res/icons/find.png',
                                   r'fa/res/icons/find_all.png',
                                   r'fa/res/icons/save.png',
                                   r'fa/res/icons/settings.png',
                                   r'fa/res/icons/suitcase.png']),
                (r'fa/commands', ['fa/commands/alias']),
                ],
    install_requires=['keystone-engine',
                      'capstone',
                      'click',
                      'hjson',
                      'future',
                      'configparser'],
    python_requires='>=2.7'
)
