#!/usr/bin/env python3
# Final integration: replace all localized sets + common + famous in CredentialPolicy.kt,
# and update the 5 enum bitsPerMember = log2(size) constants to match the data.
import os, re
HERE=os.environ.get("LOCDATA_DIR", os.path.dirname(os.path.abspath(__file__)))  # where merge.py wrote emit.kt.txt
KT=os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),"../../../shared/src/commonMain/kotlin/com/vg/run/CredentialPolicy.kt"))
emit=open(f"{HERE}/emit.kt.txt",encoding='utf-8').read()

# parse size comments
sizes={m.group(1):int(m.group(2)) for m in re.finditer(r'// (LOCALIZED_\w+): size (\d+)', emit)}
# parse set blocks
blocks={m.group(1):m.group(0) for m in re.finditer(r'    private val (\w+)(?:: Set<String>)? = setOf\(.*?\n    \)', emit, re.S)}

src=open(KT,encoding='utf-8').read()
def repl_set(name, typed=False):
    global src
    new=blocks[name]
    pat=r'    private val '+name+r'(?:: Set<String>)? = setOf\(.*?\n    \)'
    src2,n=re.subn(pat, lambda _:new, src, flags=re.S)
    assert n==1, f"{name}: replaced {n}"
    src=src2

for nm in ["LOCALIZED_WEEKDAYS","LOCALIZED_MONTHS","LOCALIZED_COLOURS","LOCALIZED_COMPASS","LOCALIZED_FAMILY","FAMOUS_PHRASES"]:
    repl_set(nm)
# LOCALIZED_COMMON_WORDS currently an emptySet placeholder
newc=blocks["LOCALIZED_COMMON_WORDS"]
src,n=re.subn(r'    private val LOCALIZED_COMMON_WORDS: Set<String> = emptySet\(\)', lambda _:newc, src)
if n==0:  # already a setOf from a prior run
    src,n=re.subn(r'    private val LOCALIZED_COMMON_WORDS(?:: Set<String>)? = setOf\(.*?\n    \)', lambda _:newc, src, flags=re.S)
assert n==1, f"COMMON: {n}"

# enum bitsPerMember = log2(size)
ENUM={'LOCALIZED_WEEKDAY':'LOCALIZED_WEEKDAYS','LOCALIZED_MONTH':'LOCALIZED_MONTHS','LOCALIZED_COLOUR':'LOCALIZED_COLOURS','LOCALIZED_COMPASS':'LOCALIZED_COMPASS','LOCALIZED_FAMILY':'LOCALIZED_FAMILY'}
for ec,setn in ENUM.items():
    sz=sizes[setn]
    src,n=re.subn(ec+r'\(log2\([0-9.]+\)\)', f'{ec}(log2({sz}.0))', src)
    assert n==1, f"enum {ec}: {n}"

open(KT,"w",encoding='utf-8').write(src)
print("integrated. sizes:",sizes)
print("common:", blocks['LOCALIZED_COMMON_WORDS'].count('"')//2, "famous:", blocks['FAMOUS_PHRASES'].count('"')//2)
