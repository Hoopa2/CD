#!/usr/bin/env python3
"""
Token Definitions for Security-Aware Lexer
Week 4 Deliverable: Token Class Definitions
"""

class Token:
    """Base token class with position tracking"""
    def __init__(self, type, value, line, column):
        self.type = type
        self.value = value
        self.line = line
        self.column = column
    
    def __str__(self):
        return f"Token({self.type}, '{self.value}', line={self.line}, col={self.column})"
    
    def __repr__(self):
        return self.__str__()

class SecurityToken(Token):
    """Extended token class for security-specific tokens"""
    
    # Base C token types (0-999)
    IDENTIFIER = 0
    NUMBER = 1
    STRING = 2
    KEYWORD = 3
    OPERATOR = 4
    PUNCTUATOR = 5
    
    # Security token types (1000-1999)
    SECURITY_DIRECTIVE = 1000
    POLICY_DIRECTIVE = 1001
    REQUIRE_DIRECTIVE = 1002
    
    # Security annotations (1100-1199)
    AT_SECURE = 1100
    AT_CRYPTO = 1101
    AT_NETWORK = 1102
    AT_SECRET = 1103
    AT_ENCRYPTED = 1104
    AT_SANITIZED = 1105
    
    # Security levels (1200-1299)
    SECURITY_BASELINE = 1200
    SECURITY_ENHANCED = 1201
    SECURITY_CRITICAL = 1202
    SECURITY_CUSTOM = 1203
    
    SENSITIVITY_HIGH = 1210
    SENSITIVITY_MEDIUM = 1211
    SENSITIVITY_LOW = 1212
    
    # Cryptographic tokens (1300-1399)
    CRYPTO_ALGO_AES = 1300
    CRYPTO_ALGO_SHA256 = 1301
    CRYPTO_ALGO_ECDSA = 1302
    CRYPTO_ALGO_ED25519 = 1303
    
    CRYPTO_KEY_128 = 1310
    CRYPTO_KEY_192 = 1311
    CRYPTO_KEY_256 = 1312
    CRYPTO_KEY_384 = 1313
    
    CRYPTO_MODE_GCM = 1320
    CRYPTO_MODE_CTR = 1321
    CRYPTO_MODE_CBC = 1322
    
    # Network security tokens (1400-1499)
    NET_PROTOCOL_MQTT = 1400
    NET_PROTOCOL_COAP = 1401
    NET_PROTOCOL_HTTP = 1402
    NET_PROTOCOL_HTTPS = 1403
    
    NET_ENCRYPTION_TLS = 1410
    NET_ENCRYPTION_DTLS = 1411
    NET_ENCRYPTION_NONE = 1412
    
    NET_AUTH_CERTIFICATE = 1420
    NET_AUTH_TOKEN = 1421
    NET_AUTH_OAUTH = 1422
    
    # Security violation tokens (1500-1599)
    VIOLATION_HARDCODED_SECRET = 1500
    VIOLATION_WEAK_CRYPTO = 1501
    VIOLATION_INSECURE_PROTOCOL = 1502
    VIOLATION_NO_BOUNDS_CHECK = 1503
    VIOLATION_INSECURE_RNG = 1504
    
    # Secret detection tokens (1600-1699)
    POTENTIAL_SECRET = 1600
    API_KEY_PATTERN = 1601
    PRIVATE_KEY_PATTERN = 1602
    PASSWORD_PATTERN = 1603
    JWT_TOKEN_PATTERN = 1604
    
    # Policy tokens (1700-1799)
    POLICY_RULE = 1700
    POLICY_SEVERITY_CRITICAL = 1701
    POLICY_SEVERITY_HIGH = 1702
    POLICY_SEVERITY_MEDIUM = 1703
    POLICY_SEVERITY_LOW = 1704
    
    @staticmethod
    def get_token_name(token_type):
        """Convert token type to human-readable name"""
        token_map = {
            # Security directives
            SecurityToken.SECURITY_DIRECTIVE: "SECURITY_DIRECTIVE",
            SecurityToken.POLICY_DIRECTIVE: "POLICY_DIRECTIVE",
            SecurityToken.REQUIRE_DIRECTIVE: "REQUIRE_DIRECTIVE",
            
            # Security annotations
            SecurityToken.AT_SECURE: "@secure",
            SecurityToken.AT_CRYPTO: "@crypto",
            SecurityToken.AT_NETWORK: "@network",
            SecurityToken.AT_SECRET: "@secret",
            
            # Security violations
            SecurityToken.VIOLATION_HARDCODED_SECRET: "VIOLATION_HARDCODED_SECRET",
            SecurityToken.VIOLATION_WEAK_CRYPTO: "VIOLATION_WEAK_CRYPTO",
            
            # Secret detection
            SecurityToken.POTENTIAL_SECRET: "POTENTIAL_SECRET",
            SecurityToken.API_KEY_PATTERN: "API_KEY_PATTERN",
        }
        
        # Check C tokens first
        if token_type < 1000:
            c_token_map = {
                SecurityToken.IDENTIFIER: "IDENTIFIER",
                SecurityToken.NUMBER: "NUMBER",
                SecurityToken.STRING: "STRING",
                SecurityToken.KEYWORD: "KEYWORD",
                SecurityToken.OPERATOR: "OPERATOR",
                SecurityToken.PUNCTUATOR: "PUNCTUATOR",
            }
            return c_token_map.get(token_type, f"C_TOKEN_{token_type}")
        
        # Return security token name
        return token_map.get(token_type, f"SECURITY_TOKEN_{token_type}")
    
    @staticmethod
    def is_security_token(token_type):
        """Check if token is a security token"""
        return token_type >= 1000
    
    @staticmethod
    def is_violation_token(token_type):
        """Check if token represents a security violation"""
        violation_tokens = [
            SecurityToken.VIOLATION_HARDCODED_SECRET,
            SecurityToken.VIOLATION_WEAK_CRYPTO,
            SecurityToken.VIOLATION_INSECURE_PROTOCOL,
            SecurityToken.VIOLATION_NO_BOUNDS_CHECK,
            SecurityToken.VIOLATION_INSECURE_RNG
        ]
        return token_type in violation_tokens

# Test the token definitions
if __name__ == "__main__":
    print("Security Token Definitions")
    print("=" * 50)
    
    # Create some test tokens
    tokens = [
        SecurityToken(SecurityToken.IDENTIFIER, "api_key", 1, 10),
        SecurityToken(SecurityToken.AT_SECRET, "@secret", 2, 5),
        SecurityToken(SecurityToken.POTENTIAL_SECRET, "sk_live_12345", 3, 15),
        SecurityToken(SecurityToken.VIOLATION_HARDCODED_SECRET, "password='admin'", 4, 20)
    ]
    
    for token in tokens:
        token_name = SecurityToken.get_token_name(token.type)
        is_security = SecurityToken.is_security_token(token.type)
        is_violation = SecurityToken.is_violation_token(token.type)
        
        print(f"{token_name}: {token.value}")
        print(f"  Line: {token.line}, Column: {token.column}")
        print(f"  Is Security Token: {is_security}")
        print(f"  Is Violation: {is_violation}")
        print()