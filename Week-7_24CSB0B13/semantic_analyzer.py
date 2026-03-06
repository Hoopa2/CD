# Week-7/semantic_analyzer.py (Fixed Version)
import json
from collections import defaultdict
import os
import sys
from enum import Enum
from datetime import datetime

class SecurityLevel(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"

class TaintStatus(Enum):
    CLEAN = "clean"
    TAINTED = "tainted"
    SANITIZED = "sanitized"

class SymbolTable:
    def __init__(self):
        self.scopes = [defaultdict(dict)]
        self.current_scope = 0
        self.errors = []
        self.warnings = []
        self.security_attributes = defaultdict(dict)
        
    def enter_scope(self):
        self.scopes.append(defaultdict(dict))
        self.current_scope += 1
    
    def exit_scope(self):
        if len(self.scopes) > 1:
            self.scopes.pop()
            self.current_scope -= 1
    
    def add_symbol(self, name, symbol_type, attributes=None):
        if name in self.scopes[-1]:
            self.errors.append(f"Redeclaration of '{name}'")
            return False
        
        # Enhanced security attributes
        security_attrs = {
            'security_level': SecurityLevel.PUBLIC.value,
            'taint_status': TaintStatus.CLEAN.value,
            'is_credential': False,
            'is_sensitive': False,
            'requires_encryption': False
        }
        
        # Auto-detect sensitive data
        if attributes:
            # Check for credential patterns in variable names
            if any(keyword in name.lower() for keyword in 
                   ['password', 'key', 'secret', 'token', 'auth', 'credential', 'pass']):
                security_attrs['is_credential'] = True
                security_attrs['security_level'] = SecurityLevel.SECRET.value
                self.warnings.append({
                    'type': 'CREDENTIAL_DETECTED',
                    'message': f"Potential credential '{name}' - ensure proper handling",
                    'line': attributes.get('lineno', 0)
                })
            
            # Check for hard-coded sensitive values
            if 'value' in attributes and attributes['value']:
                value = attributes['value']
                if isinstance(value, str) and len(value) > 8:
                    # If it's a credential variable with a hard-coded value
                    if security_attrs['is_credential']:
                        self.warnings.append({
                            'type': 'HARDCODED_CREDENTIAL',
                            'message': f"Hard-coded credential value in '{name}'",
                            'line': attributes.get('lineno', 0)
                        })
        
        symbol_info = {
            'type': symbol_type,
            'scope': self.current_scope,
            'attributes': attributes or {},
            'security': security_attrs
        }
        
        self.scopes[-1][name] = symbol_info
        
        # Print debug info
        print(f"    ➕ Added symbol: {name} ({symbol_type}) - Credential: {security_attrs['is_credential']}")
        
        return True
    
    def lookup(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None
    
    def get_symbol_security(self, name):
        symbol = self.lookup(name)
        if symbol:
            return symbol.get('security', {})
        return None

class SemanticAnalyzer:
    def __init__(self):
        # Get the directory where this script is located
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # AST loading
        possible_paths = [
            os.path.join(self.script_dir, '..', 'Week-6', 'ast_output.json'),
            os.path.join(self.script_dir, 'ast_output.json'),
            os.path.join(os.getcwd(), 'ast_output.json')
        ]
        
        self.ast = None
        self.ast_path = None
        for path in possible_paths:
            if os.path.exists(path):
                print(f"Found AST at: {path}")
                self.ast_path = path
                self.ast = self.load_ast(path)
                break
        
        if not self.ast:
            print("ERROR: ast_output.json not found!")
            sys.exit(1)
            
        self.symbol_table = SymbolTable()
        self.security_violations = []
        self.insecure_patterns = []
        
    def load_ast(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"✓ Loaded AST from {filename}")
                return data
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return None
    
    def check_insecure_patterns(self, node):
        """Check for common insecure patterns in IoT firmware"""
        node_type = node.get('type', '')
        line = node.get('lineno', 0)
        
        print(f"    Checking node: {node_type} at line {line}")
        
        # Pattern 1: Weak cryptographic algorithms
        weak_crypto = {
            'DES': 'DES is deprecated, use AES',
            'MD5': 'MD5 is broken for security, use SHA-256',
            'SHA1': 'SHA-1 is deprecated, use SHA-256',
            'RC4': 'RC4 is insecure, use AES-GCM',
            'ECB': 'ECB mode is insecure, use CBC or GCM'
        }
        
        if node_type == 'CRYPTO_CALL':
            algo = node.get('value', '')
            print(f"      Found crypto call: {algo}")
            
            # Check for weak crypto
            for weak, message in weak_crypto.items():
                if weak in algo:
                    self.security_violations.append({
                        'type': 'WEAK_CRYPTO',
                        'severity': 'HIGH',
                        'message': f"Weak cryptography: {message}",
                        'line': line,
                        'recommendation': f"Replace {weak} with secure alternative"
                    })
                    print(f"      ⚠️  Detected weak crypto: {weak}")
            
            # Check if AES is used (good)
            if 'AES' in algo:
                print(f"      ✓ AES encryption detected (good)")
        
        # Pattern 2: Hard-coded credentials
        if node_type == 'VAR_DECL':
            var_name = None
            var_value = None
            
            # Parse variable declaration
            for child in node.get('children', []):
                if isinstance(child, str):
                    var_name = child
                    print(f"      Found variable: {var_name}")
                elif isinstance(child, dict) and child.get('type') == 'ASSIGN':
                    for subchild in child.get('children', []):
                        if isinstance(subchild, dict) and subchild.get('type') == 'STRING':
                            var_value = subchild.get('value', '')
                            print(f"      Found value: {var_value}")
            
            # Check for hard-coded credentials
            if var_name and any(keyword in var_name.lower() for keyword in 
                               ['pass', 'key', 'secret', 'token', 'auth', 'password']):
                if var_value:
                    self.security_violations.append({
                        'type': 'HARDCODED_CREDENTIAL',
                        'severity': 'CRITICAL',
                        'message': f"Hard-coded credential in '{var_name}' = '{var_value}'",
                        'line': line,
                        'recommendation': "Use secure storage or key management"
                    })
                    print(f"      🔴 CRITICAL: Hard-coded credential detected!")
        
        # Pattern 3: Unsafe string operations
        unsafe_functions = ['strcpy', 'strcat', 'sprintf', 'gets']
        if node_type == 'FUNC_CALL' and node.get('value') in unsafe_functions:
            self.security_violations.append({
                'type': 'UNSAFE_FUNCTION',
                'severity': 'HIGH',
                'message': f"Unsafe function '{node.get('value')}' used",
                'line': line,
                'recommendation': f"Use safe alternatives: strncpy/strncat/snprintf/fgets"
            })
    
    def analyze_node(self, node):
        if not node:
            return
        
        node_type = node.get('type', '')
        
        if node_type == 'PROGRAM':
            print("\n📦 Analyzing PROGRAM node")
            self.analyze_children(node)
            
        elif node_type == 'FUNCTION':
            func_name = node.get('value', 'unknown')
            print(f"\n🔧 Analyzing function: {func_name}")
            self.symbol_table.enter_scope()
            self.symbol_table.add_symbol(func_name, 'function', {
                'return_type': node.get('return_type', 'void'),
                'lineno': node.get('lineno', 0)
            })
            self.analyze_children(node)
            self.symbol_table.exit_scope()
            
        elif node_type == 'VAR_DECL':
            # First add to symbol table
            var_name = None
            for child in node.get('children', []):
                if isinstance(child, str):
                    var_name = child
                    break
            
            if var_name:
                # Extract value if present
                attributes = {'lineno': node.get('lineno', 0)}
                for child in node.get('children', []):
                    if isinstance(child, dict) and child.get('type') == 'ASSIGN':
                        for subchild in child.get('children', []):
                            if isinstance(subchild, dict) and subchild.get('type') == 'STRING':
                                attributes['value'] = subchild.get('value', '')
                
                self.symbol_table.add_symbol(var_name, 'variable', attributes)
        
        # Run security pattern checks on all nodes
        self.check_insecure_patterns(node)
        
        # Analyze children
        self.analyze_children(node)
    
    def analyze_children(self, node):
        for child in node.get('children', []):
            if isinstance(child, dict):
                self.analyze_node(child)
    
    def generate_detailed_report(self):
        """Generate comprehensive semantic analysis report"""
        report = []
        report.append("=" * 70)
        report.append("SECURE IOT COMPILER - SEMANTIC ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"\nAnalysis Timestamp: {datetime.now()}")
        report.append(f"AST Source: {self.ast_path}")
        report.append("\n")
        
        # Summary statistics
        total_issues = len(self.security_violations)
        total_warnings = len(self.symbol_table.warnings)
        total_errors = len(self.symbol_table.errors)
        
        critical = sum(1 for v in self.security_violations if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in self.security_violations if v.get('severity') == 'HIGH')
        medium = sum(1 for v in self.security_violations if v.get('severity') == 'MEDIUM')
        low = sum(1 for v in self.security_violations if v.get('severity') == 'LOW')
        
        report.append("📊 ANALYSIS SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Security Issues: {total_issues}")
        report.append(f"  ├─ CRITICAL: {critical}")
        report.append(f"  ├─ HIGH: {high}")
        report.append(f"  ├─ MEDIUM: {medium}")
        report.append(f"  └─ LOW: {low}")
        report.append(f"Total Warnings: {total_warnings}")
        report.append(f"Total Errors: {total_errors}")
        report.append("\n")
        
        # Symbol Table Summary
        report.append("📋 SYMBOL TABLE SUMMARY")
        report.append("-" * 40)
        total_symbols = sum(len(scope) for scope in self.symbol_table.scopes)
        report.append(f"Total Scopes: {len(self.symbol_table.scopes)}")
        report.append(f"Total Symbols: {total_symbols}")
        
        # List all symbols
        if total_symbols > 0:
            report.append("\nSymbols by scope:")
            for i, scope in enumerate(self.symbol_table.scopes):
                if scope:
                    report.append(f"  Scope {i}:")
                    for name, info in scope.items():
                        sec_info = info.get('security', {})
                        cred_flag = "🔑" if sec_info.get('is_credential') else "  "
                        report.append(f"    {cred_flag} {name}: {info['type']}")
        
        report.append("\n")
        
        # Security Issues Detail
        if self.security_violations:
            report.append("🔒 SECURITY ISSUES FOUND")
            report.append("-" * 40)
            
            for i, issue in enumerate(self.security_violations, 1):
                report.append(f"\n{i}. {issue['type']} (Severity: {issue.get('severity', 'UNKNOWN')})")
                report.append(f"   Line {issue['line']}: {issue['message']}")
                if 'recommendation' in issue:
                    report.append(f"   → {issue['recommendation']}")
        
        # Warnings
        if self.symbol_table.warnings:
            report.append("\n⚠️  WARNINGS")
            report.append("-" * 40)
            for warning in self.symbol_table.warnings:
                if isinstance(warning, dict):
                    report.append(f"  • {warning.get('message', warning)}")
                else:
                    report.append(f"  • {warning}")
        
        # Recommendations
        report.append("\n📝 SECURITY RECOMMENDATIONS")
        report.append("-" * 40)
        
        if critical > 0:
            report.append("  • Fix critical issues immediately before deployment")
        if any(v['type'] == 'HARDCODED_CREDENTIAL' for v in self.security_violations):
            report.append("  • Move credentials to secure hardware storage or use key management")
        if any(v['type'] == 'WEAK_CRYPTO' for v in self.security_violations):
            report.append("  • Upgrade to modern cryptographic algorithms (AES-256, SHA-256)")
        
        return "\n".join(report)
    
    def run_analysis(self):
        print("=" * 60)
        print("WEEK 7: SEMANTIC ANALYSIS & SYMBOL TABLE")
        print("=" * 60)
        print(f"Output files will be saved in: {self.script_dir}")
        print()
        
        if not self.ast:
            print("No AST to analyze!")
            return False
        
        print("\n🔍 AST Structure:")
        print(f"  Type: {self.ast.get('type')}")
        print(f"  Children count: {len(self.ast.get('children', []))}")
        print()
        
        print("Starting semantic analysis...\n")
        self.analyze_node(self.ast)
        
        # Generate comprehensive report
        report_content = self.generate_detailed_report()
        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        print(report_content)
        
        # Save results
        self.save_results(report_content)
        return True
        
    def save_results(self, report_content):
        """Save results with proper Unicode handling in Week-7 folder"""
        
        # Save structured JSON
        results = {
            'symbol_table': {},
            'warnings': self.symbol_table.warnings,
            'security_violations': self.security_violations,
            'statistics': {
                'total_issues': len(self.security_violations),
                'total_warnings': len(self.symbol_table.warnings),
                'total_errors': len(self.symbol_table.errors)
            }
        }
        
        # Build symbol table dictionary
        for i, scope in enumerate(self.symbol_table.scopes):
            # Convert defaultdict to dict for JSON serialization
            scope_dict = {}
            for name, info in scope.items():
                scope_dict[name] = info
            results['symbol_table'][f'scope_{i}'] = scope_dict
        
        # Save JSON in Week-7 folder
        json_path = os.path.join(self.script_dir, 'semantic_analysis.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Save text report with UTF-8 encoding in Week-7 folder
        report_path = os.path.join(self.script_dir, 'semantic_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # Save HTML report in Week-7 folder
        html_report = self.generate_html_report()
        html_path = os.path.join(self.script_dir, 'semantic_report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        # Save ASCII version without emojis for compatibility
        safe_report = report_content.replace('📊', '[DATA]')\
                                   .replace('🔒', '[SECURITY]')\
                                   .replace('⚠️', '[WARNING]')\
                                   .replace('✅', '[OK]')\
                                   .replace('📋', '[LIST]')\
                                   .replace('📝', '[NOTE]')\
                                   .replace('🔑', '[KEY]')
        
        ascii_path = os.path.join(self.script_dir, 'semantic_report_ascii.txt')
        with open(ascii_path, 'w', encoding='ascii', errors='ignore') as f:
            f.write(safe_report)
        
        print("\n✅ Results saved in Week-7 folder:")
        print(f"   • {json_path}")
        print(f"   • {report_path}")
        print(f"   • {ascii_path}")
        print(f"   • {html_path}")
        print("\n" + "=" * 60)
        print("WEEK 7 COMPLETE! ✓")
        print("Ready for Week 8: Data-Flow Analysis")
        print("=" * 60)
    
    def generate_html_report(self):
        """Generate HTML report for better visualization"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Compiler - Semantic Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .critical { background: #e74c3c; color: white; padding: 10px; }
                .high { background: #e67e22; color: white; padding: 10px; }
                .medium { background: #f1c40f; padding: 10px; }
                .low { background: #3498db; color: white; padding: 10px; }
                .issue { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #4CAF50; color: white; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Secure IoT Compiler - Semantic Analysis Report</h1>
                <p>Generated: """ + str(datetime.now()) + """</p>
                <p>Output Location: Week-7 folder</p>
            </div>
        """
        
        # Add summary table
        html += """
            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Count</th></tr>
                <tr><td>Total Security Issues</td><td>""" + str(len(self.security_violations)) + """</td></tr>
                <tr><td>Critical Issues</td><td>""" + str(sum(1 for v in self.security_violations if v.get('severity') == 'CRITICAL')) + """</td></tr>
                <tr><td>High Issues</td><td>""" + str(sum(1 for v in self.security_violations if v.get('severity') == 'HIGH')) + """</td></tr>
                <tr><td>Total Warnings</td><td>""" + str(len(self.symbol_table.warnings)) + """</td></tr>
                <tr><td>Total Symbols</td><td>""" + str(sum(len(scope) for scope in self.symbol_table.scopes)) + """</td></tr>
            </table>
        """
        
        # Add issues
        if self.security_violations:
            html += "<h2>Security Issues</h2>"
            for issue in self.security_violations:
                severity_class = issue.get('severity', 'MEDIUM').lower()
                html += f"""
                <div class="issue {severity_class}">
                    <h3>{issue['type']} (Severity: {issue.get('severity', 'UNKNOWN')})</h3>
                    <p><strong>Line:</strong> {issue['line']}</p>
                    <p><strong>Message:</strong> {issue['message']}</p>
                    <p><strong>Recommendation:</strong> {issue.get('recommendation', 'N/A')}</p>
                </div>
                """
        else:
            html += "<p>✓ No security issues found!</p>"
        
        html += "</body></html>"
        return html

if __name__ == "__main__":
    analyzer = SemanticAnalyzer()
    analyzer.run_analysis()