# Cryptography System Overview

This repository contains the cryptographic engine used by our company to secure client data. The core logic is implemented in `main.py`, leveraging the ChaCha20-Poly1305 authenticated encryption algorithm and AES GCM for file streaming encryption.

## Encryption Process

- **Algorithm:** [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439) (AEAD)
- **Key Management:** Encryption keys are never hardcoded; they are securely generated and managed.
- **Nonce Handling:** Each encryption operation uses a unique, randomly generated nonce.
- **Authentication:** Data integrity and authenticity are ensured via Poly1305 MAC.
- **No Static Secrets:** No static keys, salts, or parameters are present in the codebase.

## Security Assurance

Publishing this code does **not** weaken the security of your encrypted data. According to [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle), the security of a cryptographic system must rely solely on the secrecy of the key, not the secrecy of the algorithm or its implementation. As long as keys and other sensitive parameters are not embedded in the code, making the source public does not compromise security.

**Best Practices:**
- Never hardcode secrets in the codebase.
- Use secure environments and hardware security modules (HSM) for key management.
- Rotate keys and secrets regularly.
- Avoid nonce reuse and use strong, random salts.

For more information, see:
- [OWASP Cheat Sheet Series: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Information Security Stack Exchange](https://security.stackexchange.com/)

---

## Suggestion

Anyone is welcome to audit this code and suggest improvements. If you have feedback or recommendations, please contact us by email at: [contact@spunky.dev](mailto:contact@spunky.dev).

---

**Disclaimer:** This repository does not contain any confidential keys or secrets.