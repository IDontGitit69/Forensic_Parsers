import base64, gzip, re

payload = "YOUR_BASE64_STRING_HERE"

# Clean the string
payload = payload.replace("\n", "").replace("\r", "").replace(" ", "")
clean = re.sub(r'[^A-Za-z0-9+/=]', '', payload)
clean += "=" * (4 - len(clean) % 4)

# Decode base64
decoded_bytes = base64.b64decode(clean, validate=False)

# Try gzip decompression first
try:
    result = gzip.decompress(decoded_bytes).decode("utf-8")
    print("Gzip decompressed:", result)
except Exception as e:
    print(f"Not gzip ({e}), trying raw UTF-8...")
    result = decoded_bytes.decode("utf-8", errors="replace")
    print(result)
```

The key insight is that the **exfiltration chain in this payload was**:
```
query result → gzip → base64
```

So to reverse it you need to go the other direction:
```
base64 → gzip decompress → plaintext
