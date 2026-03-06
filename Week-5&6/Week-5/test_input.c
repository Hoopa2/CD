/*
 * Test IoT Firmware with Security Vulnerabilities
 * This file contains intentional security issues for testing
 */

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

// SECURITY VIOLATION: Hard-coded credentials
char* wifi_password = "homewifi123";
char* api_key = "sk_live_1234567890abcdef";

// SECURITY VIOLATION: Weak crypto algorithm
void calculate_hash(const char* data) {
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)data, strlen(data), md5_hash);
}

// SECURITY VIOLATION: Insecure string function
void copy_data(char* dest, const char* src) {
    strcpy(dest, src);  // No bounds checking!
}

// SECURITY VIOLATION: Insecure random number
int generate_token() {
    return rand();  // Not cryptographically secure
}

// Good practice example
void secure_example() {
    // Secure initialization
    char buffer[100];
    const char* secure_key = get_key_from_secure_storage();
    
    // Secure copy with bounds checking
    strncpy(buffer, secure_key, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

// Network communication examples
void insecure_network() {
    // VIOLATION: HTTP without TLS
    http_get("http://example.com/data");
    
    // VIOLATION: Plain MQTT
    mqtt_connect("iot.example.com", 1883);
}

void secure_network() {
    // Good: HTTPS with TLS
    https_get("https://example.com/data");
    
    // Good: MQTT with TLS
    mqtt_connect_tls("iot.example.com", 8883);
}

// Main function
int main() {
    printf("IoT Device Starting...\n");
    
    // Test cases
    copy_data(buffer, "test data");
    calculate_hash("sensitive information");
    
    return 0;
}