import argparse
from pathlib import Path

from config_loader import DEFAULT_CONFIG, CONFIG_PATH, _encrypt_config
from crypto_utils import load_master_key


def main():
    parser = argparse.ArgumentParser(
        description="Create or rotate the encrypted config file without writing plaintext to disk."
    )
    parser.add_argument("--max-upload-mb", type=int, default=DEFAULT_CONFIG["max_upload_mb"])
    parser.add_argument(
        "--output",
        type=Path,
        default=CONFIG_PATH,
        help="Location for encrypted config (default: config/encrypted_config.bin)",
    )
    args = parser.parse_args()

    config = DEFAULT_CONFIG.copy()
    config["max_upload_mb"] = max(1, args.max_upload_mb)

    key = load_master_key("CONFIG_MASTER_KEY")
    encrypted = _encrypt_config(config, key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encrypted)
    print(f"Encrypted config written to {args.output} (values stored only in ciphertext).")


if __name__ == "__main__":
    main()
