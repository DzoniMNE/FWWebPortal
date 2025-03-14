The set of scripts has become a Python package to make code reuse less copy-pasty.

Most of the tools are in tuitfw/tools and can be run as Python modules:

PYTHONPATH=/path/to/this/directory python3 -m tuitfw.tools.getrules -c aixboms2barracuda.yaml
PYTHONPATH=/path/to/this/directory python3 -m tuitfw.tools.updaterules -c netplane2barracuda.yaml
