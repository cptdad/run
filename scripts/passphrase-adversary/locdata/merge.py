#!/usr/bin/env python3
# Merge localized-category + common-word JSON and canonicalize the famous-phrase corpus;
# emit Kotlin literals for CredentialPolicy.kt.
# Two normalizations, matching the two Kotlin mechanisms EXACTLY:
#   normword()  = CredentialPolicy.normalizeWord  (lowercase, fold native digits, keep
#                 letters+digits INCLUDING diacritics) -> closed-category + common lookups
#   canon()     = CredentialPolicy.canonicalFold   (also folds Latin diacritics, Arabic
#                 letters/harakat, strips non-alnum) -> famous-phrase match
import json, re, sys, glob, os, math
HERE=os.path.dirname(os.path.abspath(__file__))
KT=os.path.normpath(os.path.join(HERE,"../../../shared/src/commonMain/kotlin/com/vg/run/CredentialPolicy.kt"))
TSV=os.environ.get("ACCEPTED_TSV", os.path.join(HERE,"accepted.tsv"))  # output of a passphrase-adversary run

FOLD={
 'à':'a','á':'a','â':'a','ã':'a','ä':'a','å':'a','ą':'a','ā':'a','ă':'a','æ':'ae',
 'ç':'c','ć':'c','č':'c','è':'e','é':'e','ê':'e','ë':'e','ę':'e','ě':'e','ē':'e','ė':'e',
 'ì':'i','í':'i','î':'i','ï':'i','ī':'i','į':'i','ł':'l','ñ':'n','ń':'n','ň':'n',
 'ò':'o','ó':'o','ô':'o','õ':'o','ö':'o','ø':'o','ő':'o','ō':'o','œ':'oe','ß':'ss',
 'š':'s','ś':'s','ş':'s','ù':'u','ú':'u','û':'u','ü':'u','ů':'u','ű':'u','ū':'u',
 'ý':'y','ÿ':'y','ž':'z','ź':'z','ż':'z','ð':'d','þ':'th','ё':'е',
}
def fold_digit(c):
    o=ord(c)
    if 0x0660<=o<=0x0669: return chr(ord('0')+o-0x0660)
    if 0x06F0<=o<=0x06F9: return chr(ord('0')+o-0x06F0)
    return c
def is_arabic_mark(c):
    o=ord(c)
    return (0x064B<=o<=0x065F) or o==0x0670 or o==0x0640 or (0x06D6<=o<=0x06ED) or (0x0300<=o<=0x036F)
ARABIC_FOLD={'ٱ':'ا','أ':'ا','إ':'ا','آ':'ا','ؤ':'و','ئ':'ي','ى':'ي','ی':'ي','ک':'ك','ة':'ه'}
def canon(s):
    out=[]
    for ch in s.lower():
        ch=fold_digit(ch); ch=ARABIC_FOLD.get(ch,ch)
        if ch in FOLD: out.append(FOLD[ch]); continue
        if is_arabic_mark(ch): continue
        if ch.isalnum(): out.append(ch)
    return ''.join(out)
def normword(s):          # mirrors Kotlin normalizeWord: diacritics KEPT
    out=[]
    for ch in s.lower():
        ch=fold_digit(ch)
        if ch.isalnum(): out.append(ch)
    return ''.join(out)

src=open(KT,encoding='utf-8').read()
def kset(name):
    m=re.search(r'private val '+name+r'(?:: Set<String>)? = setOf\((.*?)\n    \)', src, re.S)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
EXISTING=set()
for n in ['DIGIT_WORDS','LOCALIZED_DIGIT_WORDS','WEEKDAYS','MONTHS','NATO_ALPHABET','COLOURS','PLANETS','COMMON_WORDS']:
    EXISTING|=kset(n)
EXIST_C={canon(x) for x in EXISTING}

groups=[json.load(open(f,encoding='utf-8')) for f in sorted(glob.glob(f"{HERE}/group*.json")) if '-supp' not in f]
supps=[json.load(open(f,encoding='utf-8')) for f in sorted(glob.glob(f"{HERE}/group*-supp.json"))]
print(f"loaded {len(groups)} group + {len(supps)} supp files", file=sys.stderr)

PRUNE_N=set(); PRUNE_C=set()
for g in groups+supps:
    for x in g.get('prune',[]):
        PRUNE_N.add(normword(x)); PRUNE_C.add(canon(x))
def known(m):   # m already normword
    return m in EXISTING or canon(m) in EXIST_C or m in PRUNE_N or canon(m) in PRUNE_C

CATS=['weekdays','months','colours','compass','family']
EXTRA={'weekdays':'weekdays_extra','months':'months_extra','colours':'colours_extra'}
assigned=set(); out_cats={}
for cat in CATS:
    members=set()
    srcs=[(g,cat) for g in groups]
    if cat in EXTRA: srcs+=[(s,EXTRA[cat]) for s in supps]
    for g,key in srcs:
        for w in g.get(key,[]):
            m=normword(w)
            if not m or (len(m)<=2 and m.isascii()): continue
            if known(m) or m in assigned: continue
            members.add(m)
    out_cats[cat]=sorted(members); assigned|=members

common=set()
for s in supps:
    for w in s.get('common',[]):
        m=normword(w)
        if not m or (len(m)<=2 and m.isascii()): continue
        if known(m) or m in assigned: continue   # disjoint from the closed categories
        common.add(m)
common=sorted(common)

FAM_CATS={'proverb','lyric','quote','anthem','prayer','saying','rhyme','slogan','pangram','idiom'}
famous=set()
if os.path.exists(TSV):
    for i,line in enumerate(open(TSV,encoding='utf-8')):
        if i==0: continue
        p=line.rstrip('\n').split('\t')
        if len(p)>=6 and p[2] in FAM_CATS:
            c=canon(p[5])
            if len(c)>=15: famous.add(c)
for g in groups:
    for ph in g.get('famous',[]):
        c=canon(ph)
        if len(c)>=15: famous.add(c)
famous=sorted(famous)

def kt_set(name, items, typed=False):
    decl=f'    private val {name}'+(': Set<String>' if typed else '')+' = setOf('
    lines=[decl]; row='        '
    for it in items:
        tok=f'"{it}", '
        if len(row)+len(tok)>100: lines.append(row.rstrip()); row='        '
        row+=tok
    if row.strip(): lines.append(row.rstrip())
    lines.append('    )')
    return '\n'.join(lines)

OUT=f"{HERE}/emit.kt.txt"
NAMES={'weekdays':'LOCALIZED_WEEKDAYS','months':'LOCALIZED_MONTHS','colours':'LOCALIZED_COLOURS','compass':'LOCALIZED_COMPASS','family':'LOCALIZED_FAMILY'}
with open(OUT,'w',encoding='utf-8') as f:
    for cat in CATS:
        n=len(out_cats[cat])
        f.write(f"// {NAMES[cat]}: size {n}  bitsPerMember=log2({n})={math.log2(n):.3f}\n")
        f.write(kt_set(NAMES[cat],out_cats[cat])+"\n\n")
    f.write(f"// LOCALIZED_COMMON_WORDS: size {len(common)}  (half credit)\n")
    f.write(kt_set('LOCALIZED_COMMON_WORDS',common,typed=True)+"\n\n")
    f.write(f"// FAMOUS_PHRASES: size {len(famous)}  (canonical; min 15 chars)\n")
    f.write(kt_set('FAMOUS_PHRASES',famous,typed=True)+"\n")

sizes={NAMES[c]:len(out_cats[c]) for c in CATS}
print("category sizes:",sizes, file=sys.stderr)
print("common:",len(common),"famous:",len(famous), file=sys.stderr)
print("bitsPerMember:",{k:round(math.log2(v),3) for k,v in sizes.items()}, file=sys.stderr)
print("wrote",OUT, file=sys.stderr)
