#!/usr/bin/env python3
"""
WEEK 8: Data-Flow Analysis for Security
Author: B. Amardeep (24CSB0B13)
"""

import json
from week5_lexer import SecureLexer
from week6_parser import SecureParser
from week7_semantic_analyzer import SemanticAnalyzer
from test_loader import load_test_firmware

class TaintTracker:
    def __init__(self):
        self.tainted_vars = set()
        self.taint_sources = {}
        self.taint_propagation = []
    
    def add_taint_source(self, var_name, line, reason):
        self.tainted_vars.add(var_name)
        self.taint_sources[var_name] = {
            'line': line,
            'reason': reason
        }
    
    def propagate_taint(self, from_var, to_var, line, operation):
        if from_var in self.tainted_vars:
            self.tainted_vars.add(to_var)
            self.taint_sources[to_var] = {
                'line': line,
                'source': from_var,
                'operation': operation
            }
            self.taint_propagation.append({
                'from': from_var,
                'to': to_var,
                'line': line,
                'operation': operation
            })

class DataFlowAnalyzer:
    def __init__(self, ast, symbol_table, tokens):
        self.ast = ast
        self.symbol_table = symbol_table
        self.tokens = tokens
        self.taint_tracker = TaintTracker()
        self.data_flow_graph = []
        self.violations = []
        
        self.sensitive_vars = ['API_KEY', 'PASSWORD', 'SECRET_TOKEN']
        self.leak_sinks = ['printf', 'mqtt_publish', 'http_post', 'write_to_log']
    
    def analyze(self):
        print("\n=== Starting Data-Flow Security Analysis ===")
        
        # Identify taint sources (sensitive variables)
        self.identify_taint_sources()
        
        # Track data flow
        self.track_data_flow()
        
        # Detect leaks
        self.detect_leaks()
        
        print(f"✅ Data-flow analysis complete")
        print(f"   Tainted variables: {len(self.taint_tracker.tainted_vars)}")
        print(f"   Data flow edges: {len(self.data_flow_graph)}")
        print(f"   Leak violations: {len(self.violations)}")
        
        return self.data_flow_graph
    
    def identify_taint_sources(self):
        for token in self.tokens:
            if hasattr(token, 'value') and token.value in self.sensitive_vars:
                self.taint_tracker.add_taint_source(
                    token.value,
                    token.line,
                    f"Sensitive variable declaration"
                )
                print(f"   📍 Taint source: {token.value} at line {token.line}")
    
    def track_data_flow(self):
        # Track assignments and function calls
        for i, token in enumerate(self.tokens):
            if hasattr(token, 'value'):
                # Look for assignments
                if token.value == '=' and i > 0 and i < len(self.tokens)-1:
                    lhs = self.tokens[i-1].value if hasattr(self.tokens[i-1], 'value') else None
                    rhs = self.tokens[i+1].value if hasattr(self.tokens[i+1], 'value') else None
                    
                    if lhs and rhs and rhs in self.taint_tracker.tainted_vars:
                        self.taint_tracker.propagate_taint(rhs, lhs, token.line, 'assignment')
                        print(f"   🔄 Taint propagated: {rhs} → {lhs} at line {token.line}")
    
    def detect_leaks(self):
        for token in self.tokens:
            if hasattr(token, 'value'):
                if token.value in self.leak_sinks:
                    # Check previous token for tainted data
                    for t in self.tokens:
                        if hasattr(t, 'value') and t.value in self.taint_tracker.tainted_vars:
                            if abs(t.line - token.line) < 3:  # Close to the sink
                                self.violations.append({
                                    'phase': 'DATAFLOW',
                                    'line': token.line,
                                    'type': 'SENSITIVE_DATA_LEAK',
                                    'sink_function': token.value,
                                    'leaked_variable': t.value,
                                    'severity': 'CRITICAL',
                                    'message': f'Sensitive data {t.value} leaked via {token.value}',
                                    'suggestion': 'Encrypt or redact sensitive data before output'
                                })
    
    def get_violations(self):
        return self.violations
    
    def generate_report(self):
        return {
            'phase': 'Data-Flow Analysis (Week 8)',
            'tainted_variables': list(self.taint_tracker.tainted_vars),
            'taint_sources': self.taint_tracker.taint_sources,
            'data_flow_edges': len(self.taint_tracker.taint_propagation),
            'data_flow_graph': self.taint_tracker.taint_propagation,
            'leak_violations': len(self.violations),
            'violations': self.violations
        }

def main():
    print("="*60)
    print("WEEK 8: DATA-FLOW SECURITY ANALYSIS")
    print("="*60)
    
    # Load YOUR test_firmware.c
    print("\n📂 Loading test_firmware.c...")
    test_code = load_test_firmware()
    
    # Run previous phases
    print("\n🔤 Running Lexer...")
    lexer = SecureLexer()
    tokens = lexer.tokenize(test_code)
    
    print("\n🔨 Running Parser...")
    parser = SecureParser(tokens)
    ast = parser.parse()
    
    print("\n📊 Running Semantic Analysis...")
    analyzer = SemanticAnalyzer(ast, tokens)
    symbol_table = analyzer.analyze()
    
    # Data-flow analysis
    print("\n🌊 Running Data-Flow Analysis...")
    dataflow = DataFlowAnalyzer(ast, symbol_table, tokens)
    dataflow.analyze()
    
    print("\n🔍 TAINT TRACKING:")
    print("="*40)
    print(f"   Tainted variables: {dataflow.taint_tracker.tainted_vars}")
    
    print("\n📈 DATA FLOW PROPAGATION:")
    print("="*40)
    for edge in dataflow.taint_tracker.taint_propagation:
        print(f"   Line {edge['line']}: {edge['from']} → {edge['to']} [{edge['operation']}]")
    
    print("\n⚠️  DATA LEAK VIOLATIONS:")
    print("="*40)
    for v in dataflow.get_violations():
        print(f"\n   [{v['severity']}] Line {v['line']}: {v['type']}")
        print(f"   📍 Leaked: {v['leaked_variable']} via {v['sink_function']}")
        print(f"   💡 {v['suggestion']}")
    
    report = dataflow.generate_report()
    with open('week8_dataflow_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Report saved to week8_dataflow_report.json")

if __name__ == "__main__":
    main()