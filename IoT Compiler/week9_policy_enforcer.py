#!/usr/bin/env python3
"""
WEEK 9: Policy Enforcement Engine
Author: B. Amardeep (24CSB0B13)
"""

import json
from datetime import datetime
from week5_lexer import SecureLexer
from week6_parser import SecureParser
from week7_semantic_analyzer import SemanticAnalyzer
from week8_dataflow_analyzer import DataFlowAnalyzer
from test_loader import load_test_firmware

class PolicyEnforcer:
    def __init__(self):
        self.policies = {
            'policy_name': 'default_iot_policy',
            'security_level': 'HIGH',
            'target_device': 'constrained_iot',
            'energy_aware': True,
            'rules': [
                {'id': 'R001', 'name': 'NO_HARDCODED_KEYS', 'enabled': True, 'action': 'BLOCK'},
                {'id': 'R002', 'name': 'STRONG_CRYPTO_ONLY', 'enabled': True, 'action': 'BLOCK'},
                {'id': 'R003', 'name': 'SECURE_PROTOCOLS', 'enabled': True, 'action': 'BLOCK'},
                {'id': 'R004', 'name': 'MEMORY_SAFETY', 'enabled': True, 'action': 'WARN'},
                {'id': 'R005', 'name': 'DISABLE_DEBUG', 'enabled': True, 'action': 'WARN'},
                {'id': 'R006', 'name': 'SECURE_RANDOM', 'enabled': True, 'action': 'BLOCK'}
            ]
        }
        self.violations = []
        self.enforcement_actions = []
        self.security_score = 100
        self.compilation_successful = True
    
    def enforce(self, lexer_violations, parser_violations, semantic_violations, dataflow_violations):
        print("\n=== POLICY ENFORCEMENT ENGINE (Week 9) ===")
        print(f"📋 Policy: {self.policies['policy_name']}")
        print(f"🔒 Security Level: {self.policies['security_level']}")
        
        all_violations = []
        
        # Convert all violations to dictionaries
        for v in lexer_violations:
            if hasattr(v, 'to_dict'):
                all_violations.append(v.to_dict())
            else:
                all_violations.append(v)
        
        for v in parser_violations:
            if isinstance(v, dict):
                all_violations.append(v)
            else:
                all_violations.append({'type': str(v), 'severity': 'MEDIUM'})
        
        for v in semantic_violations:
            if isinstance(v, dict):
                all_violations.append(v)
            else:
                all_violations.append({'type': str(v), 'severity': 'MEDIUM'})
        
        for v in dataflow_violations:
            if isinstance(v, dict):
                all_violations.append(v)
            else:
                all_violations.append({'type': str(v), 'severity': 'MEDIUM'})
        
        # Apply policies
        for violation in all_violations:
            self.apply_policy(violation)
        
        # Calculate score
        self.security_score = max(0, 100 - (len(self.enforcement_actions) * 5))
        
        # Check if compilation should be blocked
        critical_blocks = [a for a in self.enforcement_actions 
                          if a['action'] == 'BLOCK' and a.get('severity') in ['CRITICAL', 'HIGH']]
        self.compilation_successful = len(critical_blocks) == 0
        
        print(f"\n📊 Enforcement Summary:")
        print(f"   Total violations: {len(all_violations)}")
        print(f"   Enforcement actions: {len(self.enforcement_actions)}")
        print(f"   Security Score: {self.security_score}/100")
        print(f"   Compilation: {'✅ SUCCESS' if self.compilation_successful else '❌ BLOCKED'}")
        
        return self.compilation_successful
    
    def apply_policy(self, violation):
        violation_type = str(violation.get('type', '')).lower()
        severity = violation.get('severity', 'MEDIUM')
        line = violation.get('line', '?')
        
        # Simple rule matching
        if 'hardcoded_key' in violation_type or 'api_key' in violation_type:
            action = 'BLOCK'
            rule = 'R001'
            name = 'NO_HARDCODED_KEYS'
        elif 'crypto' in violation_type or 'md5' in violation_type or 'des' in violation_type:
            action = 'BLOCK'
            rule = 'R002'
            name = 'STRONG_CRYPTO_ONLY'
        elif 'protocol' in violation_type or 'http' in violation_type or '1883' in violation_type:
            action = 'BLOCK'
            rule = 'R003'
            name = 'SECURE_PROTOCOLS'
        elif 'unsafe' in violation_type or 'strcpy' in violation_type:
            action = 'WARN'
            rule = 'R004'
            name = 'MEMORY_SAFETY'
        elif 'debug' in violation_type or 'printf' in violation_type:
            action = 'WARN'
            rule = 'R005'
            name = 'DISABLE_DEBUG'
        elif 'random' in violation_type or 'rand' in violation_type:
            action = 'BLOCK'
            rule = 'R006'
            name = 'SECURE_RANDOM'
        else:
            return
        
        self.enforcement_actions.append({
            'rule_id': rule,
            'rule_name': name,
            'action': action,
            'violation': violation,
            'line': line,
            'severity': severity
        })
    
    def get_enforcement_report(self):
        return {
            'timestamp': datetime.now().isoformat(),
            'policy': self.policies,
            'security_score': self.security_score,
            'compilation_successful': self.compilation_successful,
            'total_actions': len(self.enforcement_actions),
            'actions_by_rule': {},
            'enforcement_actions': self.enforcement_actions
        }
    
    def suggest_fixes(self):
        suggestions = []
        for action in self.enforcement_actions:
            violation = action['violation']
            if 'suggestion' in violation:
                suggestions.append({
                    'line': action['line'],
                    'issue': violation.get('type', 'Unknown'),
                    'suggestion': violation['suggestion']
                })
        return suggestions

def main():
    print("="*70)
    print("END-TO-END SECURE IOT FIRMWARE COMPILER - WEEK 9")
    print("POLICY ENFORCEMENT ENGINE")
    print("="*70)
    
    # Load YOUR test_firmware.c
    print("\n📂 Loading test_firmware.c...")
    test_code = load_test_firmware()
    
    print("\n🔧 Running Complete Compilation Pipeline...")
    
    # Week 5: Lexer
    print("\n[Week 5] Running Lexer...")
    lexer = SecureLexer()
    lexer.tokenize(test_code)
    lexer_violations = lexer.get_violations()
    
    # Week 6: Parser
    print("[Week 6] Running Parser...")
    parser = SecureParser(lexer.tokens)
    parser.parse()
    parser_violations = parser.get_violations()
    
    # Week 7: Semantic Analyzer
    print("[Week 7] Running Semantic Analyzer...")
    semantic = SemanticAnalyzer(parser.ast, lexer.tokens)
    semantic.analyze()
    semantic_violations = semantic.get_violations()
    
    # Week 8: Data-Flow Analyzer
    print("[Week 8] Running Data-Flow Analyzer...")
    dataflow = DataFlowAnalyzer(parser.ast, semantic.symbol_table, lexer.tokens)
    dataflow.analyze()
    dataflow_violations = dataflow.get_violations()
    
    # Week 9: Policy Enforcer
    print("[Week 9] Running Policy Enforcer...")
    enforcer = PolicyEnforcer()
    success = enforcer.enforce(
        lexer_violations,
        parser_violations,
        semantic_violations,
        dataflow_violations
    )
    
    print("\n📋 FINAL ENFORCEMENT REPORT")
    print("="*50)
    
    report = enforcer.get_enforcement_report()
    
    print(f"\nPolicy: {report['policy']['policy_name']}")
    print(f"Security Level: {report['policy']['security_level']}")
    print(f"Security Score: {report['security_score']}/100")
    print(f"Compilation: {'ALLOWED' if report['compilation_successful'] else 'BLOCKED'}")
    
    print(f"\n⚠️  ENFORCEMENT ACTIONS:")
    for action in enforcer.enforcement_actions[:10]:
        marker = "❌" if action['action'] == 'BLOCK' else "⚠️"
        print(f"  {marker} [{action['severity']}] Line {action['line']}: "
              f"{action['rule_name']} - {action['action']}")
    
    print(f"\n💡 SUGGESTED FIXES:")
    for fix in enforcer.suggest_fixes()[:5]:
        print(f"  Line {fix['line']}: {fix['suggestion']}")
    
    # Save reports
    with open('week9_policy_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    final_report = {
        'summary': {
            'project': 'End-to-End Secure IoT Firmware Compiler',
            'date': str(datetime.now()),
            'test_file': 'test_firmware.c',
            'final_status': 'SUCCESS' if success else 'FAILED'
        },
        'lexer': lexer.generate_report(),
        'parser': parser.generate_report(),
        'semantic': semantic.generate_report(),
        'dataflow': dataflow.generate_report(),
        'policy': report
    }
    
    with open('final_compilation_report.json', 'w') as f:
        json.dump(final_report, f, indent=2)
    
    print(f"\n✅ Final report saved to final_compilation_report.json")
    print(f"✅ Week 9 report saved to week9_policy_report.json")
    
    return 0 if success else 1

if __name__ == "__main__":
    main()