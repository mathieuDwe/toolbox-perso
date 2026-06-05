import subprocess
import sys

def check_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        return result.stdout.strip() or result.stderr.strip()
    except Exception as e:
        return str(e)

def main():
    print("🔍 Checking Python and pip installation...\n")

    # Check Python version
    python_version = check_command("python --version")
    print(f"Python Version: {python_version}")

    # Check pip version
    pip_version = check_command("python -m pip --version")
    print(f"pip Version: {pip_version}")

    # Check installed packages
    print("\n📦 Checking for required packages:")
    for package in ["flask", "flask_sqlalchemy", "werkzeug"]:
        result = check_command(f"python -m pip show {package}")
        if "Name:" in result:
            print(f"✅ {package} is installed.")
        else:
            print(f"❌ {package} is NOT installed.")

if __name__ == "__main__":
    main()