"""Generate or recognize a P2PKH-R1-Deferred locking script."""
import argparse
import json
from pathlib import Path
import sys

from deferred import funding_output, recognize
from shared.transaction import Output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--value', type=int, required=True, help='actual output amount in satoshis')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--public-key', metavar='HEX')
    source.add_argument('--script-file', type=Path, metavar='RAW_SCRIPT')
    parser.add_argument('--format', choices=('json', 'raw'), default='json')
    args = parser.parse_args()
    try:
        output = (
            funding_output(args.value, bytes.fromhex(args.public_key))
            if args.public_key is not None else Output(args.value, args.script_file.read_bytes())
        )
        commitment = recognize(output)
        if commitment is None:
            parser.error('script and value do not match the canonical deferred format')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == 'raw':
        sys.stdout.buffer.write(output.script)
    else:
        print(json.dumps({
            'value_sats': output.value,
            'public_key_x963': commitment.public_key.hex(),
            'target_script_sha256': commitment.script_hash.hex(),
            'target_txout_hash256': commitment.output_hash.hex(),
            'locking_script_bytes': len(output.script),
            'locking_script_hex': output.script.hex(),
        }, indent=2))


if __name__ == '__main__':
    main()
