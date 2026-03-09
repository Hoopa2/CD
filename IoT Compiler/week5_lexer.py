#!/usr/bin/env python3
"""
WEEK 5: Security-Aware Lexer
Author: B. Amardeep (24CSB0B13)
"""

import re
import json
from test_loader import load_test_firmware

class SecurityToken:
    def __init__(self, value, line_num, token_type, security_tags=None):
        self.value = value
        self.line = line_num
        self.type = token_type
        self.security_tags = security_tags or []
    
    def to_dict(self):
        return {
            'value': self.value,
            'line': self.line,
            'type': self.type,
            'security_tags': self.security_tags
        }

class SecurityViolation:
    def __init__(self, phase, line, violation_type, code, severity, suggestion=None):
        self.phase = phase
        self.line = line
        self.type = violation_type
        self.code = code
        self.severity = severity
        self.suggestion = suggestion
    
    def to_dict(self):
        return {
            'phase': self.phase,
            'line': self.line,
            'type': self.type,
            'code': self.code,
            'severity': self.severity,
            'suggestion': self.suggestion
        }

class SecureLexer:
    def __init__(self):
        self.tokens = []
        self.violations = []
        self.source_lines = []
        
        self.security_patterns = {
            'HARDCODED_KEY': {
                'pattern': r'(API_KEY|PASSWORD|SECRET_TOKEN|api_key|password|secret|token).*=\s*["\'][A-Za-z0-9+/=._-]{8,}["\']',
                'severity': 'CRITICAL',
                'suggestion': 'Use secure key storage or key management service'
            },
            'WEAK_RANDOM': {
                'pattern': r'\brand\(\)|\bsrand\(',
                'severity': 'HIGH',
                'suggestion': 'Use cryptographically secure random generator'
            },
            'UNSAFE_FUNCTION': {
                'pattern': r'\b(strcpy|strcat|gets|sprintf|printf.*%s)\(',
                'severity': 'HIGH',
                'suggestion': 'Use bounded versions: strncpy, strncat, snprintf'
            },
            'IP_ADDRESS': {
                'pattern': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'severity': 'MEDIUM',
                'suggestion': 'Avoid hardcoded IPs, use DNS or configuration'
            },
            'DEBUG_CODE': {
                'pattern': r'\b(printf|puts|DEBUG|debug_function)\b',
                'severity': 'LOW',
                'suggestion': 'Remove debug code in production'
            },
            'WEAK_CRYPTO': {
                'pattern': r'\b(MD5|DES|RC4|SHA1|MD5_|DES_|RC4_|SHA1_)\b',
                'severity': 'CRITICAL',
                'suggestion': 'Use strong algorithms: AES-256-GCM, SHA-256'
            },
            'INSECURE_PROTOCOL': {
                'pattern': r'http://|mqtt_connect.*1883',
                'severity': 'HIGH',
                'suggestion': 'Use secure protocols: HTTPS, MQTTS'
            },
            'HARDCODED_PORT': {
                'pattern': r'1883|5672|3306|5432',
                'severity': 'MEDIUM',
                'suggestion': 'Use configurable ports'
            }
        }
    
    def tokenize(self, source_code):
        self.source_lines = source_code.split('\n')
        self.tokens = []
        self.violations = []
        self._check_security_patterns()
        
        for line_num, line in enumerate(self.source_lines, 1):
            self._tokenize_line(line, line_num)
        
        self._add_security_tags()
        return self.tokens
    
    def _tokenize_line(self, line, line_num):
        i = 0
        length = len(line)
        
        while i < length:
            if line[i].isspace():
                i += 1
                continue
            
            # Handle strings
            if line[i] in '"\'':
                quote = line[i]
                j = i + 1
                while j < length and line[j] != quote:
                    if line[j] == '\\':
                        j += 2
                    else:
                        j += 1
                if j < length:
                    self.tokens.append(SecurityToken(line[i:j+1], line_num, 'STRING'))
                    i = j + 1
                else:
                    i += 1
                continue
            
            # Handle numbers
            if line[i].isdigit():
                j = i
                while j < length and (line[j].isdigit() or line[j] in 'xXabcdef.'):
                    j += 1
                self.tokens.append(SecurityToken(line[i:j], line_num, 'NUMBER'))
                i = j
                continue
            
            # Handle identifiers
            if line[i].isalpha() or line[i] == '_':
                j = i
                while j < length and (line[j].isalnum() or line[j] == '_'):
                    j += 1
                self.tokens.append(SecurityToken(line[i:j], line_num, 'IDENTIFIER'))
                i = j
                continue
            
            # Handle operators
            if line[i] in '=+-*/%&|<>!':
                self.tokens.append(SecurityToken(line[i], line_num, 'OPERATOR'))
                i += 1
                continue
            
            # Handle separators
            if line[i] in '(){}[];,.':
                self.tokens.append(SecurityToken(line[i], line_num, 'SEPARATOR'))
                i += 1
                continue
            
            i += 1
    
    def _check_security_patterns(self):
        for line_num, line in enumerate(self.source_lines, 1):
            for pattern_name, pattern_info in self.security_patterns.items():
                matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                for match in matches:
                    self.violations.append(SecurityViolation(
                        phase='LEXER',
                        line=line_num,
                        violation_type=pattern_name,
                        code=match.group().strip(),
                        severity=pattern_info['severity'],
                        suggestion=pattern_info['suggestion']
                    ))
    
    def _add_security_tags(self):
        for violation in self.violations:
            for token in self.tokens:
                if token.line == violation.line:
                    if violation.type not in token.security_tags:
                        token.security_tags.append(violation.type)
    
    def get_violations(self):
        return self.violations
    
    def get_violations_by_severity(self, severity):
        return [v for v in self.violations if v.severity == severity]
    
    def generate_report(self):
        return {
            'phase': 'Lexical Analysis (Week 5)',
            'total_tokens': len(self.tokens),
            'total_violations': len(self.violations),
            'violations_by_severity': {
                'CRITICAL': len(self.get_violations_by_severity('CRITICAL')),
                'HIGH': len(self.get_violations_by_severity('HIGH')),
                'MEDIUM': len(self.get_violations_by_severity('MEDIUM')),
                'LOW': len(self.get_violations_by_severity('LOW'))
            },
            'violations': [v.to_dict() for v in self.violations],
            'tokens': [t.to_dict() for t in self.tokens[:50]]
        }

def main():
    print("="*60)
    print("WEEK 5: SECURITY-AWARE LEXER")
    print("="*60)
    
    # Load YOUR test_firmware.c
    print("\n📂 Loading test_firmware.c...")
    test_code = load_test_firmware()
    
    lexer = SecureLexer()
    tokens = lexer.tokenize(test_code)
    
    print(f"\n📊 SUMMARY")
    print(f"   Total tokens: {len(tokens)}")
    print(f"   Security violations: {len(lexer.violations)}")
    
    print(f"\n⚠️  VIOLATIONS BY SEVERITY")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = len(lexer.get_violations_by_severity(severity))
        print(f"   {severity}: {count}")
    
    print(f"\n📝 DETAILED VIOLATIONS")
    for v in lexer.violations:
        print(f"   [{v.severity}] Line {v.line}: {v.type}")
        print(f"        Code: {v.code}")
        print(f"        Suggestion: {v.suggestion}")
        print()
    
    report = lexer.generate_report()
    with open('week5_lexer_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Report saved to week5_lexer_report.json")

if __name__ == "__main__":
    main()