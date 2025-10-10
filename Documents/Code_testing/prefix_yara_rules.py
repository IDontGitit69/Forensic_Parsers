import os
import re
import argparse

def add_prefix_to_rules(input_dir, output_master):
    # Regex to match rule definitions: e.g., rule MyRule { ... }
    rule_pattern = re.compile(r'(^\s*rule\s+)([A-Za-z0-9_]+)', re.MULTILINE)
    master_rules = []

    # Ensure output dir exists
    if not os.path.isdir(input_dir):
        raise ValueError(f"Directory not found: {input_dir}")

    # Process each .yar or .yara file
    for filename in os.listdir(input_dir):
        if not filename.lower().endswith(('.yar', '.yara')):
            continue

        file_path = os.path.join(input_dir, filename)

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        modified = False

        # Replace rule names
        def repl(match):
            prefix, name = match.groups()
            if not name.startswith("1_"):
                new_name = "1_" + name
                nonlocal modified
                modified = True
                return f"{prefix}{new_name}"
            else:
                return match.group(0)

        new_content = rule_pattern.sub(repl, content)

        # Write the updated file back if modified
        if modified:
            backup_path = file_path + ".bak"
            os.replace(file_path, backup_path)  # keep a backup
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"[+] Updated rule names in: {filename}")
        else:
            print(f"[-] No change needed: {filename}")

        master_rules.append(new_content)

    # Write all rules into a master file
    with open(output_master, "w", encoding="utf-8") as f:
        f.write("\n\n".join(master_rules))

    print(f"\n✅ Combined master YARA file written to: {output_master}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prefix YARA rule names with '1_' and combine all into one master file.")
    parser.add_argument("input_dir", help="Directory containing .yar/.yara files")
    parser.add_argument("--output", default="master_rules.yar", help="Output master YARA file path")
    args = parser.parse_args()

    add_prefix_to_rules(args.input_dir, args.output)
