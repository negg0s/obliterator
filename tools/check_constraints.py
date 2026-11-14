import os
import sys

banned_words = [
    "robust",
    "comprehensive",
    "seamless",
    "leverage",
    "utilize",
    "powerful",
    "blazing",
    "cutting-edge",
    "game changer",
    "it's worth noting",
    "in order to",
    "delve",
    "delving",
    "tapestry",
    "multifaceted",
    "plethora",
    "testament",
    "revolutionize",
    "unleash",
    "pivotal",
    "foster",
    "streamline",
]

banned_chars = ["\u2014", "\u2013", "\u2015", "\u2212"]

violations = []
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for dirpath, dirnames, filenames in os.walk(root_dir):
    if ".git" in dirpath or "build" in dirpath:
        continue
    for fname in filenames:
        if fname == "check_constraints.py":
            continue
        if fname.endswith((".cpp", ".hpp", ".h", ".txt", ".md", ".yml", ".yaml", ".json", ".cmd", ".bat", ".py", ".ps1", ".psm1", ".psd1")):
            fpath = os.path.join(dirpath, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for c in banned_chars:
                    if c in content:
                        violations.append((fpath, f"Banned char {repr(c)}"))
                for w in banned_words:
                    if w in content.lower():
                        violations.append((fpath, f"Banned word '{w}'"))
                for char in content:
                    cp = ord(char)
                    if (
                        (0x1F600 <= cp <= 0x1F64F)
                        or (0x1F300 <= cp <= 0x1F5FF)
                        or (0x1F680 <= cp <= 0x1F6FF)
                        or (0x1F1E0 <= cp <= 0x1F1FF)
                        or (0x2600 <= cp <= 0x26FF)
                        or (0x2700 <= cp <= 0x27BF)
                    ):
                        violations.append((fpath, f"Emoji {repr(char)}"))
                        break

if violations:
    print(f"Violations found ({len(violations)}):")
    for fpath, v in violations:
        print(f"  {fpath}: {v}")
    sys.exit(1)
else:
    print("Zero violations found across all repository files.")
    sys.exit(0)
