#!/usr/bin/env python3
"""
WEEK 7: Symbol Table & Semantic Analysis
Author: B. Amardeep (24CSB0B13)
"""

import json
from week5_lexer import SecureLexer
from week6_parser import SecureParser
from test_loader import load_test_firmware

class Symbol:
    def __init__(self, name, symbol_type, line_declared, scope):
        self.name = name
        self.type = symbol_type
        self.line_declared = line_declared
        self.scope = scope
        self.security_sensitive = False
        self.initialized = False
        self.used = False
        self.references = []
        self.security_tags = []
    
    def to_dict(self):
        return {
            'name': self.name,
            'type': self.type,
            'line_declared': self.line_declared,
            'scope': self.scope,
            'security_sensitive': self.security_sensitive,
            'initialized': self.initialized,
            'used': self.used,
            'references': self.references,
            'security_tags': self.security_tags
        }

class Scope:
    def __init__(self, scope_name, parent=None):
        self.name = scope_name
        self.parent = parent
        self.symbols = {}
        self.children = []
    
    def add_symbol(self, symbol):
        self.symbols[symbol.name] = symbol

class SemanticAnalyzer:
    def __init__(self, ast, tokens):
        self.ast = ast
        self.tokens = tokens
        self.global_scope = Scope("global")
        self.current_scope = self.global_scope
        self.symbol_table = {}
        self.violations = []
        
        self.sensitive_patterns = {
            'key': ['API_KEY', 'SECRET_TOKEN', 'api_key'],
            'password': ['PASSWORD', 'password'],
            'token': ['SECRET_TOKEN', 'token'],
            'credential': ['auth', 'credential']
        }
        
        self.semantic_rules = [
            {
                'id': 'SEM001',
                'name': 'Uninitialized Sensitive Variable',
                'severity': 'HIGH'
            },
            {
                'id': 'SEM002',
                'name': 'Type Mismatch in Crypto Operation',
                'severity': 'HIGH'
            },
            {
                'id': 'SEM004',
                'name': 'Insecure Default Values',
                'severity': 'MEDIUM'
            }
        ]
    
    def analyze(self):
        print("\n=== Starting Semantic Security Analysis ===")
        
        # Build symbol table from tokens
        self.build_symbol_table()
        
        # Check for violations
        self.check_violations()
        
        print(f"✅ Semantic analysis complete")
        print(f"   Symbols found: {len(self.symbol_table)}")
        print(f"   Security violations: {len(self.violations)}")
        print(f"   Sensitive variables: {len([s for s in self.symbol_table.values() if s.security_sensitive])}")
        
        return self.symbol_table
    
    def build_symbol_table(self):
        for token in self.tokens:
            if hasattr(token, 'type') and token.type == 'IDENTIFIER':
                if token.value not in self.symbol_table:
                    symbol = Symbol(token.value, 'variable', token.line, 'global')
                    
                    # Check if sensitive
                    for category, patterns in self.sensitive_patterns.items():
                        if any(p in token.value for p in patterns):
                            symbol.security_sensitive = True
                            symbol.security_tags.append(category)
                            break
                    
                    self.symbol_table[token.value] = symbol
    
    def check_violations(self):
        # Check for weak crypto functions in tokens
        weak_crypto = ['MD5', 'DES', 'RC4', 'SHA1', 'rand']
        for token in self.tokens:
            if hasattr(token, 'value'):
                if token.value in weak_crypto:
                    self.violations.append({
                        'phase': 'SEMANTIC',
                        'line': token.line,
                        'type': f'WEAK_CRYPTO_FUNCTION',
                        'function': token.value,
                        'severity': 'CRITICAL',
                        'rule_id': 'SEM002',
                        'message': f'Weak cryptographic function {token.value} detected',
                        'suggestion': 'Use strong algorithms like AES-256-GCM or SHA-256'
                    })
                
                # Check for unsafe functions
                if token.value in ['strcpy', 'strcat', 'gets', 'sprintf']:
                    self.violations.append({
                        'phase': 'SEMANTIC',
                        'line': token.line,
                        'type': 'UNSAFE_FUNCTION',
                        'function': token.value,
                        'severity': 'HIGH',
                        'rule_id': 'SEM004',
                        'message': f'Unsafe function {token.value} detected',
                        'suggestion': f'Use bounded version instead'
                    })
                
                # Check for insecure protocols
                if 'http://' in token.value or '1883' in str(token.value):
                    self.violations.append({
                        'phase': 'SEMANTIC',
                        'line': token.line,
                        'type': 'INSECURE_PROTOCOL',
                        'severity': 'HIGH',
                        'rule_id': 'SEM004',
                        'message': 'Insecure protocol detected',
                        'suggestion': 'Use HTTPS or MQTTS'
                    })
    
    def get_violations(self):
        return self.violations
    
    def generate_report(self):
        return {
            'phase': 'Semantic Analysis (Week 7)',
            'total_symbols': len(self.symbol_table),
            'sensitive_symbols': len([s for s in self.symbol_table.values() if s.security_sensitive]),
            'total_violations': len(self.violations),
            'violations_by_severity': {
                'CRITICAL': len([v for v in self.violations if v.get('severity') == 'CRITICAL']),
                'HIGH': len([v for v in self.violations if v.get('severity') == 'HIGH']),
                'MEDIUM': len([v for v in self.violations if v.get('severity') == 'MEDIUM']),
                'LOW': len([v for v in self.violations if v.get('severity') == 'LOW'])
            },
            'symbol_table': {name: sym.to_dict() for name, sym in self.symbol_table.items()},
            'violations': self.violations
        }

def main():
    print("="*60)
    print("WEEK 7: SYMBOL TABLE & SEMANTIC ANALYSIS")
    print("="*60)
    
    # Load YOUR test_firmware.c
    print("\n📂 Loading test_firmware.c...")
    test_code = load_test_firmware()
    
    # Get tokens from lexer
    print("\n🔤 Running Lexer...")
    lexer = SecureLexer()
    tokens = lexer.tokenize(test_code)
    
    # Parse tokens
    print("\n🔨 Running Parser...")
    parser = SecureParser(tokens)
    ast = parser.parse()
    
    # Semantic analysis
    print("\n📊 Running Semantic Analysis...")
    analyzer = SemanticAnalyzer(ast, tokens)
    symbol_table = analyzer.analyze()
    
    # Print violations
    print("\n⚠️  SEMANTIC VIOLATIONS:")
    print("="*40)
    violations_by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    
    for v in analyzer.get_violations():
        severity = v.get('severity', 'MEDIUM')
        if severity in violations_by_severity:
            violations_by_severity[severity].append(v)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if violations_by_severity[severity]:
            print(f"\n   {severity}:")
            for v in violations_by_severity[severity]:
                print(f"     Line {v.get('line', '?')}: {v.get('type', 'Unknown')}")
                if 'message' in v:
                    print(f"        {v['message']}")
                if 'suggestion' in v:
                    print(f"        💡 {v['suggestion']}")
                print()
    
    report = analyzer.generate_report()
    with open('week7_semantic_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Report saved to week7_semantic_report.json")

if __name__ == "__main__":
    main()