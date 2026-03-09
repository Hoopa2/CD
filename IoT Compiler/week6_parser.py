#!/usr/bin/env python3
"""
WEEK 6: Parser & AST with Security Nodes
Author: B. Amardeep (24CSB0B13)
"""

import json
from week5_lexer import SecureLexer, SecurityToken, SecurityViolation
from test_loader import load_test_firmware

class ASTNode:
    def __init__(self, node_type, line_num=0):
        self.type = node_type
        self.line = line_num
        self.children = []
        self.security_tags = []
    
    def add_child(self, child):
        self.children.append(child)
    
    def __repr__(self, level=0):
        ret = "  " * level + f"└─ {self.type}"
        if self.security_tags:
            ret += f" [SEC: {', '.join(self.security_tags)}]"
        ret += "\n"
        for child in self.children:
            ret += child.__repr__(level + 1)
        return ret
    
    def to_dict(self):
        return {
            'type': self.type,
            'line': self.line,
            'security_tags': self.security_tags,
            'children': [c.to_dict() for c in self.children]
        }

class SecurityNode(ASTNode):
    def __init__(self, node_type, line_num, security_type):
        super().__init__(node_type, line_num)
        self.security_type = security_type
        self.security_tags.append(security_type)

class SecureParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.position = 0
        self.current_token = None
        self.ast = []
        self.security_nodes = []
        self.violations = []
        
        self.security_functions = {
            'crypto': ['MD5', 'SHA1', 'DES', 'RC4', 'AES', 'encrypt', 'decrypt'],
            'network': ['connect', 'mqtt', 'http', 'socket', 'send'],
            'memory': ['malloc', 'free', 'memcpy', 'strcpy', 'strcat'],
            'debug': ['printf', 'fprintf', 'sprintf', 'puts', 'DEBUG']
        }
    
    def parse(self):
        print("\n=== Starting Security-Aware Parsing ===")
        
        while self.position < len(self.tokens):
            self.current_token = self.tokens[self.position]
            
            if hasattr(self.current_token, 'value'):
                if self.current_token.value in ['void', 'int', 'char']:
                    self.parse_function_declaration()
                else:
                    self.advance()
            else:
                self.advance()
        
        print(f"✅ Parsing complete. AST has {len(self.ast)} top-level nodes")
        print(f"🔐 Found {len(self.security_nodes)} security-sensitive nodes")
        
        return self.ast
    
    def advance(self):
        self.position += 1
        if self.position < len(self.tokens):
            self.current_token = self.tokens[self.position]
        else:
            self.current_token = None
    
    def parse_function_declaration(self):
        func_node = ASTNode('FUNCTION_DECL', self.current_token.line)
        self.advance()  # Skip return type
        
        if self.current_token and hasattr(self.current_token, 'value'):
            name_node = ASTNode('IDENTIFIER', self.current_token.line)
            name_node.add_child(ASTNode(self.current_token.value, self.current_token.line))
            func_node.add_child(name_node)
            
            # Check if function name is security-sensitive
            if self.current_token.value in ['weak_encryption', 'mqtt_connect_insecure', 
                                           'http_request', 'unsafe_copy', 'send_telemetry']:
                name_node.security_tags.append('SECURITY_ENTRY')
                self.security_nodes.append(name_node)
            
            self.advance()
            
            # Skip parameters and body (simplified for demo)
            while self.current_token and self.current_token.value != '}':
                if self.current_token and hasattr(self.current_token, 'value'):
                    # Check for security-sensitive calls
                    if self.current_token.value in ['strcpy', 'printf', 'rand', 'MD5_Init', 
                                                   'mqtt_connect', 'http_post']:
                        sec_node = SecurityNode('SECURITY_CALL', self.current_token.line, 
                                               self._get_security_category(self.current_token.value))
                        self.security_nodes.append(sec_node)
                        
                        # Add violation
                        self.violations.append({
                            'phase': 'PARSER',
                            'line': self.current_token.line,
                            'type': f'INSECURE_{self.current_token.value.upper()}_CALL',
                            'severity': 'HIGH'
                        })
                self.advance()
        
        self.ast.append(func_node)
    
    def _get_security_category(self, func_name):
        for category, funcs in self.security_functions.items():
            if any(f in func_name for f in funcs):
                return category
        return 'unknown'
    
    def get_ast(self):
        return self.ast
    
    def get_security_nodes(self):
        return self.security_nodes
    
    def get_violations(self):
        return self.violations
    
    def generate_report(self):
        return {
            'phase': 'Parser & AST Construction (Week 6)',
            'total_ast_nodes': len(self.ast),
            'security_nodes': len(self.security_nodes),
            'parser_violations': len(self.violations),
            'security_node_types': list(set([n.security_type for n in self.security_nodes if hasattr(n, 'security_type')])),
            'ast_structure': [n.to_dict() for n in self.ast],
            'security_nodes_list': [{'type': n.type, 'line': n.line, 'tags': n.security_tags} 
                                   for n in self.security_nodes]
        }

def main():
    print("="*60)
    print("WEEK 6: SECURITY-AWARE PARSER & AST")
    print("="*60)
    
    # Load YOUR test_firmware.c
    print("\n📂 Loading test_firmware.c...")
    test_code = load_test_firmware()
    
    # Get tokens from lexer
    print("\n🔤 Running Lexer first...")
    lexer = SecureLexer()
    tokens = lexer.tokenize(test_code)
    print(f"   Generated {len(tokens)} tokens")
    
    # Parse tokens
    print("\n🔨 Building AST...")
    parser = SecureParser(tokens)
    ast = parser.parse()
    
    # Print security nodes
    print("\n🔐 SECURITY-SENSITIVE NODES:")
    print("="*40)
    for node in parser.get_security_nodes():
        print(f"   Line {node.line}: {node.type} [Tags: {node.security_tags}]")
    
    # Print violations
    print("\n⚠️  PARSER-LEVEL VIOLATIONS:")
    print("="*40)
    for v in parser.get_violations():
        print(f"   Line {v['line']}: {v['type']} ({v['severity']})")
    
    report = parser.generate_report()
    with open('week6_parser_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Report saved to week6_parser_report.json")

if __name__ == "__main__":
    main()