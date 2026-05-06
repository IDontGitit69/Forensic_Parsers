import re

def generate_yara(ioc_file, output_file):
    strings_block = []
    
    with open(ioc_file) as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    for i, ioc in enumerate(iocs):
        # Detect IPs - keep case sensitive
        if re.match(r'\d+\.\d+\.\d+\.\d+', ioc):
            strings_block.append(f'        $ioc_{i} = "{ioc}"')
        else:
            # Filenames, keywords etc - case insensitive
            strings_block.append(f'        $ioc_{i} = "{ioc}" nocase')
    
    rule = f"""rule Custom_User_IOCs {{
    meta:
        description = "Auto-generated IOC rule"
        score = 75
    strings:
{chr(10).join(strings_block)}
    condition:
        any of them
}}"""
    
    with open(output_file, "w") as f:
        f.write(rule)

generate_yara("user_iocs.txt", "custom-signatures/yara/user_iocs.yar")
