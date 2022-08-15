#!/usr/bin/env python
import ast
from glob import glob


def run(file_obj):
    code = ast.parse(file_obj.read())
    for node in ast.walk(code):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
            docstring = ast.get_docstring(node)
            if docstring:
                print(docstring)
                # print(repr(docstring))


if __name__ == '__main__':
    # print(glob('tests/test_*'))

    for filename in glob('tests/test_*'):
        with open(filename, encoding='utf-8') as f:
            run(f)

# Usage:
#   python h.py > h.bat
#   h
