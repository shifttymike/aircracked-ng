import sys
import os
import subprocess
import shutil

def main():
    # 1. Check if hcxpcapngtool is installed
    if shutil.which("hcxpcapngtool") is None:
        print("Error: 'hcxpcapngtool' is not installed or not in your PATH.")
        print("Please install it first (e.g., 'sudo apt install hcxtools') and try again.")
        sys.exit(1)

    # 2. Validate Input
    if len(sys.argv) != 2:
        print("Usage: python3 crak-gen.py file.cap")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    # 3. Setup Filenames
    base_name = os.path.splitext(input_file)[0]
    hashcat_out = f"{base_name}-hashcat-22000.txt"
    john_out = f"{base_name}-john.txt"

    # Prepare commands
    cmd1 = ["hcxpcapngtool", "-o", hashcat_out, input_file]
    cmd2 = ["hcxpcapngtool", f"--john={john_out}", input_file]

    # 4. Execute and show only custom status
    try:
        # Run Hashcat conversion
        subprocess.run(cmd1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"Generated Hashcat file: {hashcat_out}")

        # Run John conversion
        subprocess.run(cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"Generated John file: {john_out}")

    except subprocess.CalledProcessError:
        print("Error: hcxpcapngtool failed to process the file.")

if __name__ == "__main__":
    main()
