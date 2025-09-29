import pickletools

with open("/home/ubuntu/harmless.pkl", "rb") as f:
    pickletools.dis(f)


