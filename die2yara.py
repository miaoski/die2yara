# -*- coding: utf8 -*-
# Convert DIE patterns into yara rules

import sys
import re
from slimit.parser import Parser
from slimit.visitors.nodevisitor import ASTVisitor
from slimit import ast

# TODO: "'7z'AABBCC"
def diestr_to_yara(x):
    quotes = re.compile(r"'([^']+)'")
    x = x.replace('"', '')
    x = x.replace('.', '?')
    x = x.replace('$', '?')
    x = x.replace('#', '?')
    xs = []
    p = -1
    for y in quotes.finditer(x):                            # XXX: UGLY
        if y.group() == '': continue
        if p > 0 and p != y.end():
            xs.append(x[p:y.start()])
        p = y.end()
        xs.append(x[y.start()+1:y.end()-1].encode('hex'))
    else:
        if p == -1:
            xs.append(x)
    x = ''.join(xs)
    r = ' '.join(a+b for a,b in zip(x[::2], x[1::2]))
    return r

class MyVisitor(ASTVisitor):
    def __init__(self):
        self.begin = False
        self.type = 'UNK'
        self.name = 'UNK'
        self.sec = 0
        self.rewind()

    def rewind(self):
        self.meta = []
        self.strings = []
        self.conditions = []
        self.i = 0

    def add_meta(self, x):
        if x[0] == 'b':
            x = x.replace(' = 1', ' = true')
            x = x.replace(' = 0', ' = false')
        self.meta.append(x)

    def add_string(self, x):
        self.i += 1
        tag = 'x%d' % self.i
        y = diestr_to_yara(x)
        self.strings.append('$%s = { %s }\t// %s' % (tag, y, x))
        return tag

    def add_condition(self, x):
        self.conditions.append(x)

    def visit_Object(self, node):
        print 'Object=', node
        for child in node:
            self.visit(child)

    def visit_FuncDecl(self, node):
        if node.children()[0].value == 'detect':    # DIE pattern begins with `function detect(...)`
            self.begin = True
        for child in node:
            self.visit(child)

    def visit_If(self, node):
        self.visit(node.predicate)
        self.visit(node.consequent)
        if isinstance(node.predicate, ast.FunctionCall):
            self.show()
            self.rewind()
        if node.alternative:
            self.visit(node.alternative)

    def call_PE_compareEP(self, args):
        if len(args) == 1:
            tag = self.add_string(args[0].value)
            self.add_condition('$%s at pe.entry_point' % (tag,))
        else:
            tag = self.add_string(args[0].value)
            self.add_condition('$%s at (pe.entry_point+%d)' % (tag, args[1].value))

    def brkt_PE_section(self, arg):
        tag = self.add_string("'" + arg.strip('"') + "'")
        self.add_condition('1 of $%s' % tag)

    def call_init(self, args):
        self.type = args[0].value.replace('"', '').replace(' ', '_')
        self.name = args[1].value.replace('"', '').replace(' ', '_')

    def visit_BracketAccessor(self, node):
        if isinstance(node.node, ast.DotAccessor):
            method = 'brkt_%s' % (node.node.to_ecma().replace('.', '_'))
            getattr(self, method, self.generic_visit)(node.expr.value)

    def visit_FunctionCall(self, node):
        if isinstance(node.identifier, ast.DotAccessor):
            method = 'call_%s_%s' % (node.identifier.node.value, node.identifier.identifier.value)
            getattr(self, method, self.generic_visit)(node.args)
        else:
            method = 'call_%s' % (node.identifier.value)
            getattr(self, method, self.generic_visit)(node.args)
        for child in node:
            self.visit(child)

    def visit_Assign(self, node):
        self.add_meta(node.to_ecma())
        for child in node:
            self.visit(child)

    def show(self):
        if len(self.strings) == 0 and len(self.conditions) == 0:
            return
        self.sec += 1
        print 'rule %s_%d : %s { ' % (self.name, self.sec, self.type)
        if len(self.meta):
            print '  meta:'
            for x in self.meta:
                print '    ' + x
        if len(self.strings):
            print '  strings:'
            for x in self.strings:
                print '    ' + x
        if len(self.conditions):
            print '  conditions:'
            print '    ' + ' AND '.join(self.conditions)
        print '}'
        print

src = open(sys.argv[1]).read()
parser = Parser()
tree = parser.parse(src)
visitor = MyVisitor()
visitor.visit(tree)
visitor.show()
