# test_loader.py
# Shared test file loader for all weeks

def load_test_firmware():
    """Load the test_firmware.c file"""
    try:
        with open('test_firmware.c', 'r') as f:
            return f.read()
    except FileNotFoundError:
        print("ERROR: test_firmware.c not found!")
        print("Please make sure test_firmware.c is in the same directory")
        exit(1)