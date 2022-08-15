#!/usr/bin/env python
import ast
from glob import glob

if __name__ == '__main__':
    # print(glob('tests/test_*'))

    for file in glob('tests/test_*'):
        with open(file, encoding='utf-8') as f:
            code = ast.parse(f.read())
            for node in ast.walk(code):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
                    docstring = ast.get_docstring(node)
                    if docstring:
                        print(docstring)
                        # print(repr(docstring))

# Usage:
#   python h.py > h.bat
#   h
