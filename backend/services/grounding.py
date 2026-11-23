"""Deterministic grounding for local-SLM output.

The small model is only allowed to say things that can be checked mechanically against the evidence rows it
cites. Everything here is plain string/number matching: it catches invented values, wrong event types,
unsupported certainty and repetition. It does NOT prove a sentence is true (see docs/USER-GUIDE.md, "SLM safety and scope").
"""
import re
from datetime import datetime

EVENTS = ('login_failed', 'login_success', 'priv_change', 'process')
RE_ID = re.compile(r'\bS\d+-E\d+\b')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_DATETIME = re.compile(r'\b(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2})(?::(\d{2}))?Z?)?')
RE_CLOCK = re.compile(r'(?<![\d:])(\d{1,2}:\d{2})(?::(\d{2}))?(?![\d:])\s*(?:[AaPp][Mm])?')
# Tokens that look like machine identifiers: contain a digit, an underscore, a backslash or an executable extension.
RE_IDENT = re.compile(r'[A-Za-z0-9_\\][A-Za-z0-9_.\\-]*[A-Za-z0-9_\\]|[A-Za-z0-9_\\]')
NUMBER_WORDS = {w: i for i, w in enumerate('zero one two three four five six seven eight nine ten eleven twelve'.split())}
STOP = set('the a an and or of to in on at by for with from as is are was were be been this that these those it its into than then '
           'which while also not no any all one two three four five six seven eight nine ten there their them they has have had may might could '
           'would should can possibly suggests suggest shows show seen record records row rows event events evidence'.split())
# Capitalised words a model may use that are not in the logs. Anything else mid-sentence must be present in the evidence.
VOCAB = set('utc ip ips mfa vpn nat rdp ssh soc siem windows linux powershell active directory administrators administrator kerberos microsoft '
            'ntlm sysmon mitre att ck i'.split())

HEDGE = re.compile(r'\b(?:may|might|could|possibly|possible|potentially|suggests?|consistent with|can indicate|would warrant|worth|unclear|not established|unknown)\b', re.I)
SPECULATION = re.compile(r'\b(?:likely|probably|may|might|could|possibly|appears? to|suggests?|indicat(?:es?|ing)|attacker|malicious|compromis\w*|intent\w*)\b', re.I)
OVERCLAIM = re.compile(
    r'\b(?:confirmed|definitely|certainly|undoubtedly|proves?|proven|conclusively)\b'
    r'|\b(?:was|were|been|is|are|has been|have been)\s+(?:successfully\s+)?(?:compromised|breached|exfiltrated|infected|hijacked|backdoored)\b'
    r'|\bmalware\s+(?:was\s+|were\s+)?(?:executed|installed|ran|running)\b'
    r'|\battackers?\s+(?:successfully\s+|then\s+)?(?:gained|accessed|stole|exfiltrated|obtained)\b'
    r'|\b(?:ransomware|exfiltration|lateral movement|data theft)\b'
    r'|\bthreat actors?\b', re.I)
GENERIC = re.compile(r'^(?:further|more)\s+(?:investigation|analysis|review)\b|^(?:it is|this is)\s+(?:important|recommended)\b|\bshould be (?:investigated|reviewed) further\b', re.I)


def words(text):
    text = RE_ID.sub(' ', text.lower())
    return {w for w in re.findall(r'[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*|\d+(?:\.\d+)*', text) if len(w) > 2 and w not in STOP}


def similar(a, b):
    """True when two statements say essentially the same thing (token overlap, order-insensitive)."""
    wa, wb = words(a), words(b)
    if min(len(wa), len(wb)) < 3:
        return a.strip().lower() == b.strip().lower()
    inter = len(wa & wb)
    return inter / min(len(wa), len(wb)) >= 0.8 or inter / len(wa | wb) >= 0.6


def _by_id(incident):
    return {r['id']: r for r in incident['rows']}


def describe(rows):
    """One deterministic sentence of facts about a set of evidence rows."""
    if not rows:
        return ''
    ev = {e: sum(r['event'] == e for r in rows) for e in EVENTS}
    parts = [f'{n} {e.replace("_", " ")}' for e, n in ev.items() if n]
    known = lambda key: sorted({r[key] for r in rows if r[key] not in ('unknown', '-')})
    out = ', '.join(parts) or f'{len(rows)} events'
    for label, key in (('user', 'user'), ('device', 'device'), ('source IP', 'ip')):
        vals = known(key)
        if vals:
            out += f'; {label}{"s" if len(vals) > 1 else ""} {", ".join(vals)}'
    first, last = rows[0]['time'], rows[-1]['time']
    return out + (f'; {first} to {last}' if first != last else f'; at {first}')


def facts(incident):
    """Facts computed from the rows (not by the model). They are given to the model and define which counts are allowed."""
    lookup = _by_id(incident)
    return [dict(rule=f['rule'], text=f'{f["title"]}: {describe([lookup[i] for i in f["evidence"] if i in lookup])}', evidence_ids=f['evidence'])
            for f in incident['findings']]


def limitations(incident):
    """Incident-specific limitations derived from the data and the rules that fired, never written by the model."""
    rows, rules = incident['rows'], set(incident['rules'])
    ev = {r['event'] for r in rows}
    out = []
    if 'priv_change' in ev:
        out.append('Approval status comes from the log field "approved"; it is not verified and the change ticket and actor were not examined.')
    if 'process' in ev:
        out.append('Only the command line is recorded: parent process, signer and execution outcome are not in the evidence.')
    if 'login_failed' in ev:
        out.append('Failure reasons, lockout state and MFA outcome are not in the evidence.')
    if 'success_after' in rules:
        out.append('The later successful login is linked by account and time only; the source IP and session were not compared.')
    if rules & {'spray', 'distributed'} or len({r['ip'] for r in rows if r['ip'] != '-'}) > 1:
        out.append('Shared NAT, proxy or VPN egress can produce this pattern; no IP ownership or reputation data was used.')
    if rules & {'offhours', 'offhours_failure'}:
        out.append('Off-hours depends on the configured UTC offset and hours; no per-user schedule was used.')
    if any(r['ip'] == '-' for r in rows):
        out.append('Some evidence rows have no source IP.')
    out.append('Only rows selected by the rules are shown; other activity by these accounts or devices was not examined.')
    return out[:5]


def _numbers_in(text):
    return {int(n) for n in re.findall(r'(?<![\w.])\d+(?![\w.]|\.\d)', text)}


def _count_set(rows):
    s = {len(rows)}
    for e in EVENTS:
        s.add(sum(r['event'] == e for r in rows))
    for key in ('user', 'device', 'ip'):
        s.add(len({r[key] for r in rows if r[key] not in ('unknown', '-')}))
    return s


# "<n> [up to 2 words] <noun>" claims are checked against the matching count, not the loose set of all counts.
TYPED = [(r'fail(?:ed|ures?)|unsuccessful', ('event', 'login_failed')), (r'successful|successes|succeeded', ('event', 'login_success')),
         (r'(?:privilege|group)\s+changes?', ('event', 'priv_change')), (r'processes|commands?', ('event', 'process')),
         (r'(?:different |distinct |unique )?(?:ips?|ip addresses|sources?)', ('distinct', 'ip')),
         (r'(?:different |distinct |unique )?(?:accounts?|users?)', ('distinct', 'user')), (r'(?:different |distinct |unique )?(?:devices?|hosts?)', ('distinct', 'device'))]
RE_NUM = r'(\d+|' + '|'.join(w for w in NUMBER_WORDS if w not in ('zero', 'one')) + r')'


def _typed_allowed(kind, cited, incident):
    lookup = _by_id(incident)
    sets = [cited] + [[lookup[i] for i in f['evidence'] if i in lookup] for f in incident['findings'] if {r['id'] for r in cited} & set(f['evidence'])]
    out = set()
    for rows in sets:
        out.add(sum(r['event'] == kind[1] for r in rows) if kind[0] == 'event' else len({r[kind[1]] for r in rows if r[kind[1]] not in ('unknown', '-')}))
    return out


def typed_numbers(text, cited, incident):
    """Return (problems, spans) for numbers attached to an event/entity noun; spans are removed from the loose check."""
    why, spans = [], []
    for noun, kind in TYPED:
        for m in re.finditer(RE_NUM + r'\s+(?:[a-z-]+\s+){0,2}?(?:' + noun + r')\b', text, re.I):
            n = m.group(1).lower()
            n = int(n) if n.isdigit() else NUMBER_WORDS[n]
            if n not in _typed_allowed(kind, cited, incident):
                why.append(f'{n} {m.group(0).split(None, 1)[1]!r} does not match the cited rows')
            spans.append((m.start(1), m.end(1)))
    return why, spans


def allowed_numbers(cited, incident):
    lookup = _by_id(incident)
    ids = {r['id'] for r in cited}
    s = {0, 1, incident['score'], 30, 50, 80, 100} | _count_set(cited) | _count_set(incident['rows'])
    for f in incident['findings']:
        if ids & set(f['evidence']):
            s |= _count_set([lookup[i] for i in f['evidence'] if i in lookup]) | _numbers_in(f['title'])
    for r in cited:
        s |= _numbers_in(' '.join(str(r[k]) for k in ('user', 'device', 'ip', 'detail')))
    times = sorted(datetime.fromisoformat(r['time'].replace('Z', '+00:00')) for r in cited)
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])] + ([(times[-1] - times[0]).total_seconds()] if len(times) > 1 else [])
    for g in gaps:  # whole units, tolerant of floor/round/ceil wording
        for unit in (1, 60, 3600):
            s |= {int(g // unit), int(round(g / unit)), int(-(-g // unit))}
    return s


def problems(text, kind, cited_ids, incident):
    """Return the reasons a statement is not supported by the rows it cites (empty list = accepted)."""
    lookup = _by_id(incident)
    cited = [lookup[i] for i in dict.fromkeys(cited_ids) if i in lookup]
    why = []
    low = text.lower()
    corpus = ' '.join(' '.join(str(r[k]) for k in ('user', 'device', 'ip', 'event', 'detail', 'id')) for r in incident['rows'])
    cited_text = ' '.join(' '.join(str(r[k]) for k in ('user', 'device', 'ip', 'event', 'detail')) for r in cited).lower()
    corpus_words = set(re.findall(r'\w+', (corpus + ' ' + ' '.join(f['title'] for f in incident['findings'])).lower()))

    # 1. evidence IDs written inline must exist
    stray = set(RE_ID.findall(text)) - set(lookup)
    if stray:
        why.append('unknown evidence ID ' + ', '.join(sorted(stray)))
    # 2. IPv4 literals must come from the cited rows
    bad_ip = set(RE_IP.findall(text)) - {r['ip'] for r in cited}
    if bad_ip:
        why.append('IP not in cited rows: ' + ', '.join(sorted(bad_ip)))
    # 3. dates and clock times must match cited rows (UTC)
    row_dates = {r['time'][:10] for r in cited}
    row_hm = {r['time'][11:16] for r in cited}
    row_hms = {r['time'][11:19] for r in cited}
    bad_time = []
    for date, hm, sec in RE_DATETIME.findall(text):
        if date not in row_dates:
            bad_time.append(date)
        if hm and (hm not in row_hm or (sec and f'{hm}:{sec}' not in row_hms)):
            bad_time.append(hm + (':' + sec if sec else ''))
    for hm, sec in RE_CLOCK.findall(RE_DATETIME.sub(' ', text)):
        hm = hm.zfill(5)
        if hm not in row_hm or (sec and f'{hm}:{sec}' not in row_hms):
            bad_time.append(hm + (':' + sec if sec else ''))
    if bad_time:
        why.append('time/date not in cited rows (UTC): ' + ', '.join(dict.fromkeys(bad_time)))
    # 4. machine-like identifiers must appear in the cited rows (or at least the incident)
    scrubbed = RE_DATETIME.sub(' ', RE_IP.sub(' ', RE_ID.sub(' ', text)))
    for tok in RE_IDENT.findall(scrubbed):
        t = tok.strip('.-').lower()
        if (re.search(r'\d', t) and re.search(r'[a-z_]', t)) or '_' in t or '\\' in t or re.search(r'\.(?:exe|dll|ps1|bat|cmd|sh|py|vbs|js)$', t):
            if t not in cited_text and t not in corpus.lower():
                why.append(f'identifier not in evidence: {tok}')
            elif t not in cited_text:
                why.append(f'identifier not in cited rows: {tok}')
        elif re.fullmatch(r'[a-z]+\.[a-z]+', t) and t not in ('e.g', 'i.e') and t not in corpus.lower():
            why.append(f'account/host name not in evidence: {tok}')
    # 5. known users/devices must be in the rows that are cited
    entities = {r[k] for r in incident['rows'] for k in ('user', 'device') if r[k] not in ('unknown', '-')}
    for ent in sorted(entities):
        if re.search(r'(?<![\w.-])' + re.escape(ent) + r'(?![\w-])', text, re.I) and ent.lower() not in cited_text:
            why.append(f'{ent} is not in the cited rows')
    # 6. unknown capitalised names (mid-sentence, not acronyms, not in evidence)
    for m in re.finditer(r'(?<=[a-z,;:)] )([A-Z][a-z]{2,})\b', text):
        w = m.group(1).lower()
        if w not in corpus_words and w not in VOCAB and w not in {x for x in STOP}:
            why.append(f'name not in evidence: {m.group(1)}')
    # 7. counts and durations must be derivable from the cited rows / findings
    body = RE_IDENT.sub(lambda m: ' ' if re.search(r'[A-Za-z]', m.group(0)) and re.search(r'\d|_|\\', m.group(0)) else m.group(0), scrubbed)
    body = RE_CLOCK.sub(' ', body)
    typed_why, spans = typed_numbers(body, cited, incident)
    why += typed_why
    for a, b in spans:  # already verified above
        body = body[:a] + ' ' * (b - a) + body[b:]
    allowed = allowed_numbers(cited, incident) if cited else {0, 1}
    for n in _numbers_in(body):
        if n not in allowed:
            why.append(f'number {n} cannot be derived from cited rows')
    for w, n in NUMBER_WORDS.items():
        if n > 1 and re.search(r'\b' + w + r'\b', body.lower()) and n not in allowed:
            why.append(f'number "{w}" cannot be derived from cited rows')
    # 8. event-type consistency
    ev = {r['event'] for r in cited}
    if re.search(r'(?<!un)\bsuccessful(?:ly)?\b|\bsucceeded\b|\blogged in\b|\blogon succe', low) and 'login_success' not in ev and not re.search(r'\bno successful\b', low):
        why.append('claims a successful login but cites none')
    if re.search(r'\bfail(?:ed|ure|ures)?\b|\bunsuccessful\b|\bdenied\b', low) and re.search(r'log\s?in|logon|password|authenticat|sign.?in|attempt', low) and 'login_failed' not in ev:
        why.append('claims failed logins but cites none')
    if re.search(r'\badded to\b|\bgroup (?:change|membership)\b|\bprivilege change\b', low) and 'priv_change' not in ev:
        why.append('claims a privilege/group change but cites none')
    if re.search(r'\b(?:executed|launched|command line|process(?:es)? (?:start|creat))', low) and 'process' not in ev:
        why.append('claims process activity but cites none')
    priv = [r for r in cited if r['event'] == 'priv_change']
    if re.search(r'\bunapproved\b|\bnot approved\b|\bwithout approval\b', low) and priv and any(r['approved'] for r in priv) and not any(not r['approved'] for r in priv):
        why.append('says unapproved but cited change is marked approved')
    if re.search(r'(?<!un)(?<!not )\bapproved\b', low) and priv and not any(r['approved'] for r in priv) and not re.search(r'\bno approved\b|approved\W+(?:field|flag|status|set|value|is|was|equals|=|:)', low):
        why.append('says approved but cited change is not marked approved')
    # 9. certainty and style by section
    if OVERCLAIM.search(text):
        why.append('asserts unestablished compromise/certainty')
    if kind == 'observations' and SPECULATION.search(text):
        why.append('observation contains speculation; move to interpretations')
    if kind == 'interpretations' and not HEDGE.search(text):
        why.append('interpretation is not hedged')
    if GENERIC.search(text.strip()):
        why.append('generic statement with no incident-specific content')
    return why


def filter_statements(output, incident, limits=dict(observations=4, interpretations=2)):
    """Keep supported, non-repeated statements. Returns (accepted, rejected). Structural errors raise ValueError."""
    ids = set(_by_id(incident))
    rule_texts = [f['title'] for f in incident['findings']] + [incident['summary']]
    accepted = {'observations': [], 'interpretations': []}
    rejected, seen = [], []
    for kind in ('observations', 'interpretations'):
        items = output.get(kind)
        if not isinstance(items, list):
            raise ValueError(f'Invalid {kind}.')
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('Invalid cited statement.')
            text, cited = item.get('statement'), item.get('evidence_ids')
            if not isinstance(text, str) or not text.strip() or len(text) > 3000:
                raise ValueError('Empty or oversized statement.')
            if not isinstance(cited, list) or not cited or any(not isinstance(x, str) for x in cited):
                raise ValueError('Missing evidence references.')
            text = ' '.join(text.split())
            unknown = set(cited) - ids
            if unknown:
                reason = ['unknown evidence references: ' + ', '.join(sorted(unknown))]
            else:
                cited = list(dict.fromkeys(cited + RE_ID.findall(text)))  # inline IDs count as citations
                reason = problems(text, kind, cited, incident)
                if not reason and kind == 'observations' and any(similar(text, t) for t in rule_texts[:-1]):
                    reason = ['repeats a rule finding already shown']
                if not reason and any(similar(text, s) for s in seen):
                    reason = ['repeats an earlier statement']
            if reason:
                rejected.append(dict(section=kind, statement=text, evidence_ids=cited, reason='; '.join(dict.fromkeys(reason))))
            elif len(accepted[kind]) < limits[kind]:
                accepted[kind].append(dict(statement=text, evidence_ids=cited))
                seen.append(text)
    return accepted, rejected
