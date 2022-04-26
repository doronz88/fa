from pathlib import Path

from setuptools import setup

BASE_DIR = Path(__file__).parent.resolve(strict=True)


def parse_requirements():
    reqs = []
    with open(BASE_DIR / 'requirements.txt', 'r') as fd:
        for line in fd.readlines():
            line = line.strip()
            if line:
                reqs.append(line)
    return reqs


setup(
    name='fa',
    version='0.3.0',
    description='FA Plugin',
    author='DoronZ',
    author_email='doron88@gmail.com',
    url='https://github.com/doronz88/fa',
    packages=['fa', 'fa.commands'],
    package_dir={'fa': 'fa'},
    package_data={'': ['*.png', '*'], },
    include_package_data=True,
    data_files=[(r'fa/res/icons', [r'fa/res/icons/create_sig.png',
                                   r'fa/res/icons/export.png',
                                   r'fa/res/icons/find.png',
                                   r'fa/res/icons/find_all.png',
                                   r'fa/res/icons/save.png',
                                   r'fa/res/icons/settings.png',
                                   r'fa/res/icons/suitcase.png']),
                (r'fa/commands', ['fa/commands/alias']),
                ],
    install_requires=parse_requirements(),
    python_requires='>=2.7',
)
