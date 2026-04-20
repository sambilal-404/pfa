# Signature Engine (`signatures.py`)

## Purpose of the file
This file is the core of the **Pattern Matching** layer (Layer 1). It takes incoming request data (URL, Body, Headers) and matches it against pre-compiled Regular Expressions (Regex) to detect known attacks like SQL Injection or XSS.

## Step-by-Step Explanation
1. **Compilation:** When the engine starts, it runs `re.compile()` on all rules. This makes regex matching extremely fast because the patterns are parsed into memory once.
2. **Initialization:** The `SignatureEngine` class loads a list of `SignatureRule` objects. It immediately sorts them by `Severity` (CRITICAL first, then HIGH, etc.). This optimization means if a CRITICAL threat is found early, the engine *could* stop early (though currently it collects all matches).
3. **Analysis (`analyze` method):**
   - It takes the URL, body, and headers.
   - It filters out `excluded_headers` (like `User-Agent` or `Accept`) because these often cause false positives with complex regex.
   - It loops through every rule, checking if the rule's `pattern` matches the field using `rule.pattern.search(field_value)`.
   - If a match is found, it records exactly what matched, where it matched, and creates a `RuleMatch` object.

## Important Functions & Classes
- `_compile_pattern(pattern, flags)`: Uses `re.IGNORECASE` (so "SELECT" and "select" both match) and sometimes `re.DOTALL` (for multi-line XSS payloads).
- `SignatureRule` (from `models.py`): Uses `@dataclass(frozen=True)`. "Frozen" means immutable—once the rule is created, it cannot be accidentally modified during runtime. This is crucial for security.
- `SignatureEngine.analyze()`: The main workhorse. It combines headers into a single string to scan them efficiently.

## Real Examples from My Code
In your code, the `XSS-001` rule targets `<script>` tags:
```python
pattern=_compile_pattern(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
```
- `\s*`: allows spaces (e.g., `< script >`)
- `[^>]*`: allows attributes like `<script src="...">`
- `re.DOTALL`: ensures `.*?` matches even if the payload spans multiple lines!

## Key Decisions & Why They Matter
1. **Sorting by Severity:** You sort rules `reverse=True` based on severity index. This is a senior-level optimization trick.
2. **Excluding Headers:** By intentionally ignoring headers like `Accept-Language`, you drastically lower the False Positive rate, which is the main goal of your PFA.
3. **Pre-compiling:** `re.compile()` avoids recompiling the regex string for every single HTTP request, making your API scalable.
