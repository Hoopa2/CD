#!/usr/bin/env python3
"""
Security-Aware Lexical Analyzer (Lexer)
Week 5 Deliverable: Working Lexer with Security Tokenization
"""

import re
import sys
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama for colored output
init(autoreset=True)

# Import token definitions from Week 4
# sys.path.append('../Week-4')
from token_definitions import SecurityToken, Token

class SecurityLexer:
    """Security-aware lexical analyzer for IoT firmware"""
    
    def __init__(self, policy_file='security_policies.json'):
        """Initialize lexer with security policies"""
        self.tokens = []
        self.errors = []
        self.line_num = 1
        self.column_num = 1
        self.current_line = ""
        
        # Security patterns from policies
        self.secret_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', SecurityToken.PASSWORD_PATTERN),
            (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', SecurityToken.API_KEY_PATTERN),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', SecurityToken.POTENTIAL_SECRET),
            (r'AKIA[0-9A-Z]{16}', SecurityToken.API_KEY_PATTERN),  # AWS key
            (r'sk_live_[a-zA-Z0-9]{24}', SecurityToken.API_KEY_PATTERN),  # Stripe key
            (r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----', SecurityToken.PRIVATE_KEY_PATTERN),
            (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', SecurityToken.JWT_TOKEN_PATTERN),
        ]
        
        # Weak crypto patterns
        self.weak_crypto_patterns = [
            (r'MD5\s*\(', SecurityToken.VIOLATION_WEAK_CRYPTO),
            (r'SHA1\s*\(', SecurityToken.VIOLATION_WEAK_CRYPTO),
            (r'DES\s*\(', SecurityToken.VIOLATION_WEAK_CRYPTO),
            (r'RC4\s*\(', SecurityToken.VIOLATION_WEAK_CRYPTO),
        ]
        
        # Insecure function patterns
        self.insecure_function_patterns = [
            (r'\bstrcpy\s*\(', SecurityToken.VIOLATION_NO_BOUNDS_CHECK),
            (r'\bstrcat\s*\(', SecurityToken.VIOLATION_NO_BOUNDS_CHECK),
            (r'\bgets\s*\(', SecurityToken.VIOLATION_NO_BOUNDS_CHECK),
            (r'\bsprintf\s*\(', SecurityToken.VIOLATION_NO_BOUNDS_CHECK),
            (r'\brand\s*\(', SecurityToken.VIOLATION_INSECURE_RNG),
        ]
        
        # Insecure protocol patterns
        self.insecure_protocol_patterns = [
            (r'http://', SecurityToken.VIOLATION_INSECURE_PROTOCOL),
            (r'mqtt://', SecurityToken.VIOLATION_INSECURE_PROTOCOL),
            (r'ftp://', SecurityToken.VIOLATION_INSECURE_PROTOCOL),
        ]
        
        # Security annotation patterns
        self.annotation_patterns = [
            (r'@secret\s*\(\s*(HIGH|MEDIUM|LOW)\s*\)', SecurityToken.AT_SECRET),
            (r'@secure\s*\(', SecurityToken.AT_SECURE),
            (r'@crypto\s*\(', SecurityToken.AT_CRYPTO),
            (r'@network\s*\(', SecurityToken.AT_NETWORK),
            (r'@security\s+', SecurityToken.SECURITY_DIRECTIVE),
            (r'@policy\s+', SecurityToken.POLICY_DIRECTIVE),
        ]
        
        # C language keywords
        self.keywords = {
            'int', 'char', 'float', 'double', 'void', 'if', 'else',
            'while', 'for', 'return', 'include', 'define', 'struct'
        }
        
        # Operators and punctuators
        self.operators = set('+-*/%=&|<>!')
        self.punctuators = set(';,(){}[]#')
        
    def tokenize(self, source_code):
        """Main tokenization method"""
        print(f"{Fore.CYAN}Starting security-aware lexer analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Source code length: {len(source_code)} characters{Style.RESET_ALL}")
        
        lines = source_code.split('\n')
        for line in lines:
            self.current_line = line
            self.column_num = 1
            self.process_line(line)
            self.line_num += 1
        
        print(f"{Fore.GREEN}Tokenization complete!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total tokens: {len(self.tokens)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Security violations found: {len([t for t in self.tokens if SecurityToken.is_violation_token(t.type)])}{Style.RESET_ALL}")
        
        return self.tokens
    
    def process_line(self, line):
        """Process a single line of source code"""
        i = 0
        line_length = len(line)
        
        while i < line_length:
            char = line[i]
            
            # Skip whitespace
            if char.isspace():
                i += 1
                self.column_num += 1
                continue
            
            # Check for comments
            if char == '/' and i + 1 < line_length:
                if line[i + 1] == '/':  # Single line comment
                    break  # Skip rest of line
                elif line[i + 1] == '*':  # Multi-line comment start
                    i = self.skip_multiline_comment(line, i)
                    continue
            
            # Check for strings
            if char in ('"', "'"):
                string_token = self.process_string(line, i)
                if string_token:
                    self.tokens.append(string_token)
                    i = string_token.end_index
                    self.column_num = string_token.column + len(string_token.value)
                continue
            
            # Check for numbers
            if char.isdigit():
                number_token = self.process_number(line, i)
                if number_token:
                    self.tokens.append(number_token)
                    i = number_token.end_index
                    self.column_num = number_token.column + len(number_token.value)
                continue
            
            # Check for identifiers/keywords
            if char.isalpha() or char == '_':
                identifier_token = self.process_identifier(line, i)
                if identifier_token:
                    self.tokens.append(identifier_token)
                    i = identifier_token.end_index
                    self.column_num = identifier_token.column + len(identifier_token.value)
                    
                    # Check for security patterns after identifiers
                    self.check_security_patterns(identifier_token)
                continue
            
            # Check for operators
            if char in self.operators:
                operator_token = self.process_operator(line, i)
                if operator_token:
                    self.tokens.append(operator_token)
                    i = operator_token.end_index
                    self.column_num = operator_token.column + len(operator_token.value)
                continue
            
            # Check for punctuators
            if char in self.punctuators:
                self.tokens.append(Token(
                    SecurityToken.PUNCTUATOR,
                    char,
                    self.line_num,
                    self.column_num
                ))
                i += 1
                self.column_num += 1
                continue
            
            # Unknown character
            self.add_error(f"Unknown character '{char}'", self.line_num, self.column_num)
            i += 1
            self.column_num += 1
    
    def process_string(self, line, start_index):
        """Process string literals"""
        quote_char = line[start_index]
        value = quote_char
        i = start_index + 1
        
        while i < len(line):
            char = line[i]
            value += char
            
            if char == quote_char and line[i-1] != '\\':  # End of string
                # Create token
                token = Token(SecurityToken.STRING, value, self.line_num, self.column_num)
                token.end_index = i + 1
                
                # Check if string contains potential secrets
                self.check_string_for_secrets(value, self.line_num, self.column_num)
                
                return token
            
            i += 1
        
        # Unclosed string
        self.add_error(f"Unclosed string literal", self.line_num, self.column_num)
        token = Token(SecurityToken.STRING, value, self.line_num, self.column_num)
        token.end_index = i
        return token
    
    def process_number(self, line, start_index):
        """Process numeric literals"""
        value = ""
        i = start_index
        
        while i < len(line) and (line[i].isdigit() or line[i] in '.eE+-'):
            value += line[i]
            i += 1
        
        token = Token(SecurityToken.NUMBER, value, self.line_num, self.column_num)
        token.end_index = i
        return token
    
    def process_identifier(self, line, start_index):
        """Process identifiers and keywords"""
        value = ""
        i = start_index
        
        while i < len(line) and (line[i].isalnum() or line[i] == '_'):
            value += line[i]
            i += 1
        
        # Check if it's a keyword
        token_type = SecurityToken.KEYWORD if value in self.keywords else SecurityToken.IDENTIFIER
        
        token = Token(token_type, value, self.line_num, self.column_num)
        token.end_index = i
        return token
    
    def process_operator(self, line, start_index):
        """Process operators"""
        value = line[start_index]
        i = start_index + 1
        
        # Check for multi-character operators
        if i < len(line):
            two_char_op = value + line[i]
            if two_char_op in ('==', '!=', '<=', '>=', '++', '--', '&&', '||', '<<', '>>'):
                value = two_char_op
                i += 1
        
        token = Token(SecurityToken.OPERATOR, value, self.line_num, self.column_num)
        token.end_index = i
        return token
    
    def skip_multiline_comment(self, line, start_index):
        """Skip multiline comments"""
        i = start_index + 2  # Skip /*
        
        while i < len(line) - 1:
            if line[i] == '*' and line[i + 1] == '/':
                return i + 2  # Skip */
            i += 1
        
        return len(line)  # Unclosed comment
    
    def check_security_patterns(self, identifier_token):
        """Check for security patterns after identifiers"""
        identifier = identifier_token.value
        
        # Check for security annotations
        for pattern, token_type in self.annotation_patterns:
            if re.match(pattern, identifier):
                self.tokens.append(Token(
                    token_type,
                    identifier,
                    identifier_token.line,
                    identifier_token.column
                ))
                return
        
        # Check for weak crypto function calls
        for pattern, token_type in self.weak_crypto_patterns:
            if re.search(pattern, self.current_line):
                self.add_violation(token_type, f"Weak cryptographic algorithm: {identifier}", 
                                  identifier_token.line, identifier_token.column)
        
        # Check for insecure function calls
        for pattern, token_type in self.insecure_function_patterns:
            if re.search(pattern, self.current_line):
                self.add_violation(token_type, f"Insecure function: {identifier}", 
                                  identifier_token.line, identifier_token.column)
        
        # Check for insecure protocols
        for pattern, token_type in self.insecure_protocol_patterns:
            if re.search(pattern, self.current_line):
                self.add_violation(token_type, f"Insecure protocol: {identifier}", 
                                  identifier_token.line, identifier_token.column)
    
    def check_string_for_secrets(self, string_value, line, column):
        """Check string literals for potential secrets"""
        for pattern, token_type in self.secret_patterns:
            if re.search(pattern, string_value):
                self.add_violation(
                    SecurityToken.VIOLATION_HARDCODED_SECRET,
                    f"Potential hard-coded secret found in string: {string_value[:50]}...",
                    line,
                    column
                )
                break
    
    def add_violation(self, violation_type, message, line, column):
        """Add security violation token and error"""
        violation_token = Token(violation_type, message, line, column)
        self.tokens.append(violation_token)
        
        # Add to error log
        self.add_error(f"SECURITY VIOLATION: {message}", line, column)
    
    def add_error(self, message, line, column):
        """Add error to error log"""
        self.errors.append({
            'type': 'ERROR',
            'message': message,
            'line': line,
            'column': column,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_token_error_log(self):
        """Generate token error log"""
        log_lines = []
        
        log_lines.append("=" * 80)
        log_lines.append("SECURITY-AWARE LEXER - TOKEN ERROR LOG")
        log_lines.append("=" * 80)
        log_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log_lines.append(f"Total tokens processed: {len(self.tokens)}")
        log_lines.append(f"Total errors/violations: {len(self.errors)}")
        log_lines.append("")
        
        if self.errors:
            log_lines.append("ERRORS AND SECURITY VIOLATIONS:")
            log_lines.append("-" * 40)
            
            for error in self.errors:
                log_lines.append(f"[Line {error['line']}:{error['column']}] {error['type']}: {error['message']}")
        else:
            log_lines.append("No errors or security violations found!")
        
        log_lines.append("")
        log_lines.append("TOKEN SUMMARY:")
        log_lines.append("-" * 40)
        
        # Count token types
        token_counts = {}
        for token in self.tokens:
            token_name = SecurityToken.get_token_name(token.type)
            token_counts[token_name] = token_counts.get(token_name, 0) + 1
        
        for token_name, count in sorted(token_counts.items()):
            log_lines.append(f"{token_name}: {count}")
        
        log_lines.append("")
        log_lines.append("SECURITY VIOLATION BREAKDOWN:")
        log_lines.append("-" * 40)
        
        violation_types = [
            (SecurityToken.VIOLATION_HARDCODED_SECRET, "Hard-coded Secrets"),
            (SecurityToken.VIOLATION_WEAK_CRYPTO, "Weak Cryptography"),
            (SecurityToken.VIOLATION_INSECURE_PROTOCOL, "Insecure Protocols"),
            (SecurityToken.VIOLATION_NO_BOUNDS_CHECK, "Memory Safety"),
            (SecurityToken.VIOLATION_INSECURE_RNG, "Insecure RNG"),
        ]
        
        for violation_type, description in violation_types:
            count = len([t for t in self.tokens if t.type == violation_type])
            if count > 0:
                log_lines.append(f"{description}: {count}")
        
        log_lines.append("=" * 80)
        
        return "\n".join(log_lines)
    
    def print_tokens(self):
        """Print all tokens in a formatted way"""
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}TOKEN LIST ({len(self.tokens)} tokens):{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        for i, token in enumerate(self.tokens):
            token_name = SecurityToken.get_token_name(token.type)
            
            # Color code based on token type
            if SecurityToken.is_violation_token(token.type):
                color = Fore.RED
            elif SecurityToken.is_security_token(token.type):
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
            
            print(f"{color}[{i:3d}] {token_name:25} '{token.value[:30]:30}' "
                  f"at line {token.line:3d}, col {token.column:3d}{Style.RESET_ALL}")

def main():
    """Main function to run the lexer"""
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SECURITY-AWARE IOT FIRMWARE LEXER - WEEK 5 DELIVERABLE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    # Create lexer
    lexer = SecurityLexer()
    
    # Read test input
    try:
        with open('test_input.c', 'r') as f:
            source_code = f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: test_input.c not found!{Style.RESET_ALL}")
        print("Using default test code...")
        source_code = """
        // Test code
        char* password = "admin123";
        MD5(data, hash);
        strcpy(dest, src);
        http://example.com
        """
    
    # Tokenize the source code
    tokens = lexer.tokenize(source_code)
    
    # Print tokens
    lexer.print_tokens()
    
    # Generate and save error log
    error_log = lexer.get_token_error_log()
    
    with open('token_error_log.txt', 'w') as f:
        f.write(error_log)
    
    print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Error log saved to: token_error_log.txt{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    
    # Print error log summary
    print("\n" + error_log)
    
    return lexer

if __name__ == "__main__":
    lexer = main()