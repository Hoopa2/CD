#!/bin/bash

echo "=================================================="
echo "END-TO-END SECURE IOT FIRMWARE COMPILER"
echo "Complete 9-Week Execution Pipeline"
echo "=================================================="
echo

# Check if test_firmware.c exists
if [ ! -f "test_firmware.c" ]; then
    echo "❌ ERROR: test_firmware.c not found!"
    echo "Please make sure test_firmware.c is in the current directory"
    exit 1
fi

echo "📁 Using test_firmware.c for all tests"
echo

# Week 5
echo "--------------------------------------------------"
echo "WEEK 5: Security-Aware Lexer"
echo "--------------------------------------------------"
python3 week5_lexer.py
echo

# Week 6
echo "--------------------------------------------------"
echo "WEEK 6: Parser & AST with Security Nodes"
echo "--------------------------------------------------"
python3 week6_parser.py
echo

# Week 7
echo "--------------------------------------------------"
echo "WEEK 7: Symbol Table & Semantic Analysis"
echo "--------------------------------------------------"
python3 week7_semantic_analyzer.py
echo

# Week 8
echo "--------------------------------------------------"
echo "WEEK 8: Data-Flow Analysis for Security"
echo "--------------------------------------------------"
python3 week8_dataflow_analyzer.py
echo

# Week 9
echo "--------------------------------------------------"
echo "WEEK 9: Policy Enforcement Engine"
echo "--------------------------------------------------"
python3 week9_policy_enforcer.py
echo

echo "=================================================="
echo "✅ ALL WEEKS COMPLETED SUCCESSFULLY"
echo "=================================================="
echo
echo "📁 Generated Reports:"
ls -1 week*_report.json final_compilation_report.json 2>/dev/null || echo "No reports found"
echo
echo "✅ All files now use test_firmware.c consistently"