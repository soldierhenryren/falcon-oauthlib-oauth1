from setuptools import setup, find_packages
from codecs import open
import falcon_oauth1


def is_pkg(line):
    return line and not line.startswith(('--', 'git', '#'))


with open('requirements.txt', encoding='utf-8') as reqs:
    install_requires = [l for l in reqs.read().split('\n') if is_pkg(l)]
setup(
    name='falcon-oauthlib-oauth1',
    version=falcon_oauth1.__version__,
    description=falcon_oauth1.__doc__,
    long_description='',
    url=falcon_oauth1.__homepage__,
    author=falcon_oauth1.__author__,
    author_email=falcon_oauth1.__contact__,
    license='WTFPL',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Scientific/Engineering :: GIS',
        'Programming Language :: Python :: 2.7'],
    keywords='falcon oauth1',
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
    extras_require={'test': ['pytest'], 'docs': 'mkdocs'},
    include_package_data=True,
)
