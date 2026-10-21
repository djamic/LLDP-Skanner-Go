#!/usr/bin/env python3
"""
Uzbek Cyrillic → Latin transliteration script.
Converts an Uzbek Cyrillic markdown file to Latin script,
preserving markdown formatting, code blocks, math ($...$), 
and English/technical terms.
"""
import re
import sys
import os

# -------- Uzbek Cyrillic → Latin mapping --------
# Multi-char mappings MUST be checked first (order matters)
MULTI_MAP = {
    'Ўз': "O'z",  # Ўзбекистон -> O'zbekiston
    'ўз': "o'z",
    'Нг': 'Ng', 'нг': 'ng',
    'Еъ': 'Ye\'', 'еъ': 'ye\'',
}

SINGLE_MAP = {
    'А': 'A', 'а': 'a',
    'Б': 'B', 'б': 'b',
    'В': 'V', 'в': 'v',
    'Г': 'G', 'г': 'g',
    'Д': 'D', 'д': 'd',
    'Е': 'E', 'е': 'e',
    'Ё': 'Yo', 'ё': 'yo',
    'Ж': 'J', 'ж': 'j',
    'З': 'Z', 'з': 'z',
    'И': 'I', 'и': 'i',
    'Й': 'Y', 'й': 'y',
    'К': 'K', 'к': 'k',
    'Л': 'L', 'л': 'l',
    'М': 'M', 'м': 'm',
    'Н': 'N', 'н': 'n',
    'О': 'O', 'о': 'o',
    'П': 'P', 'п': 'p',
    'Р': 'R', 'р': 'r',
    'С': 'S', 'с': 's',
    'Т': 'T', 'т': 't',
    'У': 'U', 'у': 'u',
    'Ф': 'F', 'ф': 'f',
    'Х': 'X', 'х': 'x',
    'Ц': 'Ts', 'ц': 'ts',
    'Ч': 'Ch', 'ч': 'ch',
    'Ш': 'Sh', 'ш': 'sh',
    'Щ': 'Sh', 'щ': 'sh',
    'Ъ': "'",  'ъ': "'",
    'Ы': 'I', 'ы': 'i',
    'Э': 'E', 'э': 'e',
    'Ю': 'Yu', 'ю': 'yu',
    'Я': 'Ya', 'я': 'ya',
    # Uzbek-specific
    'Ғ': "G'", 'ғ': "g'",
    'Ҳ': 'H', 'ҳ': 'h',
    'Қ': 'Q', 'қ': 'q',
    'Ў': "O'", 'ў': "o'",
    # Soft/hard signs
    'Ь': '', 'ь': '',
}

# Words to keep as-is (English technical terms, abbreviations)
IGNORE_FILE = os.path.join(os.path.dirname(__file__), 'ignore_words.txt')

def load_ignore_words():
    words = set()
    if os.path.exists(IGNORE_FILE):
        with open(IGNORE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith('#'):
                    words.add(w)
    return words

def is_cyrillic(ch):
    """Check if a character is Cyrillic."""
    cp = ord(ch)
    return (0x0400 <= cp <= 0x04FF)

def transliterate_word(word):
    """Transliterate a single Cyrillic word to Latin."""
    result = []
    i = 0
    while i < len(word):
        # Try multi-char mappings first (2-char)
        if i + 1 < len(word):
            pair = word[i:i+2]
            if pair in MULTI_MAP:
                result.append(MULTI_MAP[pair])
                i += 2
                continue
        # Single char
        ch = word[i]
        if ch in SINGLE_MAP:
            result.append(SINGLE_MAP[ch])
        else:
            result.append(ch)
        i += 1
    return ''.join(result)

def transliterate_text(text, ignore_words):
    """
    Transliterate Cyrillic text to Latin, preserving:
    - Code blocks (```...```)
    - Inline code (`...`)
    - Math blocks ($...$, $$...$$)
    - English words / technical terms
    - Markdown syntax
    """
    lines = text.split('\n')
    result_lines = []
    in_code_block = False
    in_mermaid = False
    
    for line in lines:
        # Track code/mermaid blocks
        stripped = line.strip()
        if stripped.startswith('```'):
            if in_code_block or in_mermaid:
                in_code_block = False
                in_mermaid = False
                result_lines.append(line)
                continue
            else:
                if 'mermaid' in stripped:
                    in_mermaid = True
                else:
                    in_code_block = True
                result_lines.append(line)
                continue
        
        if in_code_block:
            # Don't transliterate code blocks (Python, etc)
            result_lines.append(line)
            continue
        
        if in_mermaid:
            # DO transliterate mermaid diagram text (Uzbek labels)
            result_lines.append(transliterate_line(line, ignore_words))
            continue
        
        # Normal line: transliterate but preserve inline code and math
        result_lines.append(transliterate_line(line, ignore_words))
    
    return '\n'.join(result_lines)

def transliterate_line(line, ignore_words):
    """Transliterate a single line, preserving inline code and math."""
    # Split by protected segments: `...`, $$...$$, $...$
    # We protect these from transliteration
    parts = []
    i = 0
    protected = False
    current = []
    
    while i < len(line):
        # Check for $$ (display math)
        if line[i:i+2] == '$$':
            if current:
                parts.append(('text', ''.join(current)))
                current = []
            # Find closing $$
            end = line.find('$$', i + 2)
            if end == -1:
                parts.append(('protected', line[i:]))
                i = len(line)
            else:
                parts.append(('protected', line[i:end+2]))
                i = end + 2
            continue
        
        # Check for $ (inline math)
        if line[i] == '$' and (i == 0 or line[i-1] != '\\'):
            if current:
                parts.append(('text', ''.join(current)))
                current = []
            end = line.find('$', i + 1)
            if end == -1:
                parts.append(('protected', line[i:]))
                i = len(line)
            else:
                parts.append(('protected', line[i:end+1]))
                i = end + 1
            continue
        
        # Check for ` (inline code)
        if line[i] == '`':
            if current:
                parts.append(('text', ''.join(current)))
                current = []
            end = line.find('`', i + 1)
            if end == -1:
                parts.append(('protected', line[i:]))
                i = len(line)
            else:
                parts.append(('protected', line[i:end+1]))
                i = end + 1
            continue
        
        current.append(line[i])
        i += 1
    
    if current:
        parts.append(('text', ''.join(current)))
    
    # Transliterate only 'text' parts
    result = []
    for ptype, ptext in parts:
        if ptype == 'protected':
            result.append(ptext)
        else:
            result.append(transliterate_segment(ptext, ignore_words))
    
    return ''.join(result)

def transliterate_segment(text, ignore_words):
    """Transliterate a text segment, word by word."""
    # Split into tokens (words and non-words)
    tokens = re.findall(r'[\w\u0400-\u04FF]+|[^\w\u0400-\u04FF]+', text)
    result = []
    for token in tokens:
        if token in ignore_words:
            result.append(token)
        elif any(is_cyrillic(ch) for ch in token):
            result.append(transliterate_word(token))
        else:
            result.append(token)
    return ''.join(result)


def main():
    if len(sys.argv) < 3:
        print("Usage: python cyr2lat.py <input.md> <output.md>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    ignore_words = load_ignore_words()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()
    
    result = transliterate_text(text, ignore_words)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(result)
    
    print(f"[OK] {input_file} -> {output_file} (Cyrillic -> Latin)")

if __name__ == '__main__':
    main()
