/**
 * test_firmware.c
 * Sample IoT Firmware for Testing the Secure Compiler
 * 
 * This file contains various security vulnerabilities that
 * our compiler should detect.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ==================== CONFIGURATION ====================

// HARDCODED SECRETS - CRITICAL VULNERABILITY
// These should be detected by Week 5 Lexer
char API_KEY[] = "sk_live_51H5XyZJ7yK9rL2mN4pQ6rS8tU0vW2xY4";
char PASSWORD[] = "admin123";
char SECRET_TOKEN[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

// Hardcoded IP and port - Should be detected
char SERVER_IP[] = "192.168.1.100";
int MQTT_PORT = 1883;  // Default MQTT port (insecure)

// ==================== WEAK CRYPTO ====================

// Week 6 Parser should detect these weak algorithms
void weak_encryption() {
    printf("Using weak encryption...\n");
    
    // MD5 - Weak hash algorithm
    unsigned char md5_hash[16];
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, "data", 4);
    MD5_Final(md5_hash, &md5_ctx);
    
    // DES - Weak encryption algorithm
    DES_cblock des_key;
    DES_key_schedule des_schedule;
    DES_set_key_checked(&des_key, &des_schedule);
    
    // RC4 - Stream cipher with vulnerabilities
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, 16, "key");
    
    // SHA1 - Weak hash algorithm
    SHA_CTX sha1_ctx;
    SHA1_Init(&sha1_ctx);
}

// ==================== INSECURE PROTOCOLS ====================

// Week 8 Data-Flow Analyzer should detect these
void mqtt_connect_insecure() {
    // MQTT without TLS - HIGH vulnerability
    struct mqtt_client client;
    mqtt_init(&client);
    mqtt_connect(&client, SERVER_IP, MQTT_PORT);  // Leaking sensitive connection
    
    printf("Connected to MQTT broker\n");
}

void http_request() {
    // HTTP instead of HTTPS - HIGH vulnerability
    char url[] = "http://iot-server.example.com/api/data";
    http_post(url, API_KEY, "sensor_data");  // Sending API key over HTTP
}

// ==================== UNSAFE MEMORY OPERATIONS ====================

// Week 7 Semantic Analysis should detect these
void unsafe_copy(char *input) {
    char buffer[10];
    
    // Buffer overflow risk - HIGH vulnerability
    strcpy(buffer, input);  // No bounds checking
    
    // Another unsafe function
    char dest[20];
    strcat(dest, input);  // No bounds checking
    
    // Format string vulnerability
    printf(input);  // Should use printf("%s", input)
}

void use_after_free() {
    char *ptr = (char*)malloc(100);
    strcpy(ptr, "sensitive data");
    free(ptr);
    // ptr is now dangling
    printf("Data: %s\n", ptr);  // Use after free - CRITICAL
}

// ==================== WEAK RANDOMNESS ====================

// Week 7/8 should detect weak random
int generate_session_id() {
    // rand() is not cryptographically secure
    return rand();  // WEAK RANDOM - HIGH vulnerability
}

char* generate_auth_token() {
    static char token[32];
    // Using weak random for authentication
    for(int i = 0; i < 31; i++) {
        token[i] = 'A' + (rand() % 26);  // Predictable
    }
    token[31] = '\0';
    return token;
}

// ==================== DEBUG CODE ====================

// Week 5 Lexer should detect debug code
void debug_function() {
#ifdef DEBUG
    // Debug code that leaks sensitive info
    printf("=== DEBUG INFORMATION ===\n");
    printf("API Key: %s\n", API_KEY);
    printf("Password: %s\n", PASSWORD);
    printf("Server: %s:%d\n", SERVER_IP, MQTT_PORT);
    
    // Dumping memory contents
    unsigned char *mem = (unsigned char*)0x20000000;
    for(int i = 0; i < 256; i++) {
        printf("%02x ", mem[i]);
    }
    printf("\n");
#endif
}

// ==================== DATA LEAKAGE ====================

// Week 8 Data-Flow should track this
void send_telemetry() {
    char telemetry_data[256];
    char buffer[512];
    
    // Collecting sensitive data
    sprintf(telemetry_data, "temp=23.5,humid=60,api_key=%s", API_KEY);
    
    // LEAK: Sending API key in telemetry
    mqtt_publish("sensor/telemetry", telemetry_data);  // CRITICAL LEAK
    
    // Another leak path
    sprintf(buffer, "Password: %s, Token: %s", PASSWORD, SECRET_TOKEN);
    write_to_log(buffer);  // Writing secrets to log file
}

// ==================== MISSING ERROR HANDLING ====================

// Week 7 should detect missing error checks
void crypto_operation() {
    unsigned char key[32];
    unsigned char plaintext[100];
    unsigned char ciphertext[120];
    
    // No error checking on crypto operations
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);  // Returns error code, not checked
    AES_encrypt(plaintext, ciphertext, &aes_key);  // No IV, wrong mode
    
    // Network operation without error check
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));  // Return value ignored
}

// ==================== MAIN FUNCTION ====================

int main() {
    printf("IoT Device Firmware Starting...\n");
    
    // Initialize
    srand(time(NULL));
    
    // Run vulnerable functions
    weak_encryption();
    mqtt_connect_insecure();
    http_request();
    
    char malicious_input[] = "This is a very long string that will cause buffer overflow if copied to a small buffer";
    unsafe_copy(malicious_input);
    
    int session = generate_session_id();
    char* token = generate_auth_token();
    
    send_telemetry();
    crypto_operation();
    
#ifdef DEBUG
    debug_function();
#endif
    
    printf("Device running. Session ID: %d\n", session);
    return 0;
}