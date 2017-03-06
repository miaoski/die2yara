# -*- coding: utf8 -*-
# Show AST of a DIE script

from slimit.parser import Parser
from slimit.visitors import nodevisitor
from slimit import ast
import sys

src = open(sys.argv[1]).read()
parser = Parser()
tree = parser.parse(src)
i = 0
for node in nodevisitor.visit(tree):
    i += 1
    print i, node, node.to_ecma()
