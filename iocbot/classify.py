from __future__ import annotations

import re

# Family (lowercase) -> primary category
FAMILY_CATEGORY = {
    # C2 frameworks / offensive tooling
    "cobalt strike": "C2", "cobaltstrike": "C2", "metasploit": "C2", "mythic": "C2",
    "sliver": "C2", "adaptixc2": "C2", "adaptix": "C2", "havoc": "C2",
    "brute ratel": "C2", "nighthawk": "C2", "covenant": "C2", "empire": "C2",
    "powershell empire": "C2", "manjusaka": "C2", "kalmarunionen": "C2",
    "kraken": "C2", "deimos": "C2", "neo": "C2", "poshc2": "C2",
    # RATs
    "njrat": "RAT", "njw0rm": "RAT", "darkcomet": "RAT", "asyncrat": "RAT",
    "async rat": "RAT", "quasar": "RAT", "quasar rat": "RAT", "nanocore": "RAT",
    "warzone": "RAT", "warzone rat": "RAT", "orcus": "RAT", "gh0st": "RAT",
    "gh0st rat": "RAT", "vshell": "RAT", "dcrat": "RAT", "dc rat": "RAT",
    "systembc": "RAT", "purevnc": "RAT", "purerat": "RAT", "pure rat": "RAT",
    "bladabindi": "RAT", "bladabindi njrat": "RAT", "adwind": "RAT",
    "jrat": "RAT", "crossrat": "RAT", "balaclava": "RAT", "zerospy": "RAT",
    "rapido": "RAT", "revenge rat": "RAT", "ab exchanger": "RAT",
    "limmer": "RAT", "venom rat": "RAT", "netwire": "RAT", "redshell": "RAT",
    "syracore": "RAT", "gafgyt": "BOTNET",
    # botnets
    "mirai": "BOTNET", "mozi": "BOTNET", "hajime": "BOTNET", "bashlite": "BOTNET",
    "gafgyt ": "BOTNET", "bashe": "BOTNET", "chaos": "BOTNET", "rapperbot": "BOTNET",
    "infectedslime": "BOTNET", "condi": "BOTNET", "hadoop": "BOTNET",
    # loaders / droppers / downloaders
    "smokeloader": "LOADER", "smoke loader": "LOADER", "guloader": "LOADER",
    "gu loader": "LOADER", "xloader": "LOADER", "formbook xloader": "LOADER",
    "hijackloader": "LOADER", "hijack loader": "LOADER", "goploader": "LOADER",
    "emotet": "LOADER", "qakbot": "LOADER", "qakbot ": "LOADER", "qbot": "LOADER",
    "icedid": "LOADER", "bumblebee": "LOADER", "bumblebee ": "LOADER",
    "pikabot": "LOADER", "socgholish": "LOADER", "clearfake": "LOADER",
    "lumma": "INFOSTEALER", "lummac2": "INFOSTEALER", "lumma c2": "INFOSTEALER",
    "mallox": "RANSOMWARE", "magniber": "RANSOMWARE",
    "cookiebot": "LOADER", "fakecaptcha": "LOADER", "fake captcha": "LOADER",
    "clearfake ": "LOADER", "silentswitcher": "LOADER", "fakeupdate": "FAKE-UPDATE",
    "fake update": "FAKE-UPDATE", "moonlock": "LOADER", "shlayer": "LOADER",
    "bundlore": "LOADER", "vize": "LOADER", "fontdrop": "LOADER",
    # infostealers
    "redline": "INFOSTEALER", "raccoon": "INFOSTEALER", "raccoon stealer": "INFOSTEALER",
    "vidar": "INFOSTEALER", "stealc": "INFOSTEALER", "meta stealer": "INFOSTEALER",
    "meta": "INFOSTEALER", "rise pro": "INFOSTEALER", "risepro": "INFOSTEALER",
    "agent tesla": "INFOSTEALER", "agenttesla": "INFOSTEALER", "lokibot": "INFOSTEALER",
    "loki bot": "INFOSTEALER", "formbook": "INFOSTEALER", "rhadamanthys": "INFOSTEALER",
    "meduza": "INFOSTEALER", "octopus": "INFOSTEALER", "oski": "INFOSTEALER",
    "dragonload": "INFOSTEALER", "darkgate": "INFOSTEALER", "titankit": "INFOSTEALER",
    "thinboy": "INFOSTEALER", "dummy": "INFOSTEALER", "stealdeal": "INFOSTEALER",
    "crealydeal": "INFOSTEALER", "radamant": "INFOSTEALER", "wikiloader": "LOADER",
    "divergent": "INFOSTEALER", "s1deload": "INFOSTEALER", "strela": "INFOSTEALER",
    # ransomware
    "lockbit": "RANSOMWARE", "alphv": "RANSOMWARE", "blackcat": "RANSOMWARE",
    "black basta": "RANSOMWARE", "cl0p": "RANSOMWARE", "clop": "RANSOMWARE",
    "royal": "RANSOMWARE", "play": "RANSOMWARE", "akira": "RANSOMWARE",
    "medusa": "RANSOMWARE", "snatch": "RANSOMWARE", "phobos": "RANSOMWARE",
    "makop": "RANSOMWARE", "conti": "RANSOMWARE", "ryuk": "RANSOMWARE",
    "revil": "RANSOMWARE", "sodinokibi": "RANSOMWARE", "hive": "RANSOMWARE",
    "babuk": "RANSOMWARE", "darkside": "RANSOMWARE", "maze": "RANSOMWARE",
    "pysa": "RANSOMWARE", "cactus": "RANSOMWARE", "fog": "RANSOMWARE",
    "lynx": "RANSOMWARE", "bianlian": "RANSOMWARE", "lynx ransomware": "RANSOMWARE",
    "hunters international": "RANSOMWARE", "ragnar locker": "RANSOMWARE",
    "ragnarlocker": "RANSOMWARE", "blackmatter": "RANSOMWARE", "holyghost": "RANSOMWARE",
    "globeimposter": "RANSOMWARE", "globelimposter": "RANSOMWARE",
    "hellokitty": "RANSOMWARE", "fivehands": "RANSOMWARE", "night sky": "RANSOMWARE",
    "monti": "RANSOMWARE", "quantum": "RANSOMWARE", "deadbolt": "RANSOMWARE",
    "payload": "RANSOMWARE", "elden": "RANSOMWARE", "sexi": "RANSOMWARE",
    "yurei": "RANSOMWARE", "rasing": "RANSOMWARE", "whisper": "RANSOMWARE",
    "crgroup": "RANSOMWARE", "mallox": "RANSOMWARE", "ranbyus": "RANSOMWARE",
    "paradise": "RANSOMWARE", "arena": "RANSOMWARE", "hunters": "RANSOMWARE",
    # botnet / stealers misc
    "etherhiding": "C2", "ether hiding": "C2",
    # cryptominers (malware distribution relevance)
    "coinminer": "MALWARE", "xmrig": "MALWARE", "outlaw": "MALWARE",
    # classic malware / bankers / trojans
    "trickbot": "MALWARE", "dridex": "MALWARE", "zeus": "MALWARE",
    "zloader": "MALWARE", "gozi": "MALWARE", "citadel": "MALWARE",
    "ramnit": "MALWARE", "upatre": "LOADER", "terdot": "MALWARE",
    "ramdo": "MALWARE", "kuluoz": "MALWARE", "murofet": "MALWARE",
    "banker": "MALWARE", "spyboy": "MALWARE", "nanocore ": "RAT",
    "sunbird": "MALWARE", "huddle": "MALWARE", "parasite": "MALWARE",
    "trojan": "MALWARE", "backdoor": "MALWARE", "rootkit": "MALWARE",
    "wiper": "MALWARE", "keylogger": "MALWARE", "remote admin tool": "RAT",
    # delivery / fake software
    "fakebrowser": "FAKE-UPDATE", "fake browser": "FAKE-UPDATE",
    "crackonel": "CRACKED-SOFTWARE", "crack": "CRACKED-SOFTWARE",
    "keygen": "CRACKED-SOFTWARE", "pirated": "PIRATED-SOFTWARE",
}

# Non-family tags that must never be treated as malware family names
FAMILY_TAG_NOISE = {
    "elf", "win", "linux", "macos", "android", "upx", "packed", "32-bit", "64-bit",
    "arm", "x86", "x64", "exe", "dll", "zip", "rar", "7z", "html", "htm", "doc",
    "docx", "pdf", "js", "vbs", "ps1", "apk", "jar", "bat", "scr", "lnk", "iso",
    "github", "issue-attachment", "opendir", "censys", "ua-wget", "backdoor",
    "drb-ra", "threatview-io", "anonymous", "compromised", "victim", "etherhiding",
    "sepolia", "clickfix", "malware_download", "payload", "botnet_cc", "amta",
    "email", "spam", "phishing", "screenshot", "miner", "coinminer", "fakecaptcha",
    "loader", "stealer", "rat", "ransomware", "apt", "c2", "hijacker", "adware",
    "pup", "pua", "banker", "trojan", "worm", "exploit", "docx", "xlsx", "rtf",
    "oneNote", "onenote", "vhd", "img", "dmg", "msi", "txt", "csv", "log", "png",
    "jpg", "gif", "svg", "css", "php", "asp", "aspx", "jsp", "py", "sh", "elf64",
}

C2_SENTENCE_RE = re.compile(
    r"command[\s\-]and[\s\-]control|\bc2\s*(?:server|servers|infrastructure|domain|domains|ip|ips|"
    r"panel|beacon|beacons|callback|node|host|traffic|channel|network|infrastructure|framework|"
    r"communication|domain|address|endpoint)s?\b|\bcallback infrastructure\b|"
    r"beacon(?:s|ing)? (?:to|from|server)|\bc2\b.{0,60}\b(?:server|domain|ip|infrastructure|host)",
    re.I,
)

MALICIOUS_SENTENCE_RE = re.compile(
    r"\bmalicious\b|\bmalware\b|\btrojan(?:ized|ised)?\b|\bbackdoor\b|\binfostealer\b|\bstealer\b|"
    r"\bransomware\b|\bbotnet\b|dropper|downloader|\bloader\b|payload|infected|exfiltrat|"
    r"credential theft|\battributed to\b|targets? (?:victims|users|systems)|keylogger|spyware|"
    r"\bRAT\b|remote access trojan|c2\b|command[\s\-]and[\s\-]control|threat actor|"
    r"\bexploit(?:ed|s)?\b|compromised|phishing|steal(?:s|ing|ed)?",
    re.I,
)

ARTICLE_CATEGORY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("C2", C2_SENTENCE_RE),
    ("RANSOMWARE", re.compile(r"ransom(?:ware)?\b|double extortion|encrypt(?:ion|ed) of (?:files|data)", re.I)),
    ("BOTNET", re.compile(r"\bbotnet\b", re.I)),
    ("RAT", re.compile(r"remote access trojan|\bRATs?\b|\bRAT\b", re.I)),
    ("INFOSTEALER", re.compile(r"infostealer|info stealer|\bstealer\b|credential[- ]harvest", re.I)),
    ("LOADER", re.compile(r"\bloaders?\b|dropper|downloader", re.I)),
    ("CRACKED-SOFTWARE", re.compile(r"\bcrack(?:ed|s|ing)?\b|keygens?|activators?|license bypass|unlicensed software", re.I)),
    ("PIRATED-SOFTWARE", re.compile(r"pirat(?:ed|es|y)|warez|unauthori[sz]ed software", re.I)),
    ("FAKE-UPDATE", re.compile(r"fake (?:browser |software |app )?update|fakeupdate|software update page|"
                               r"update (?:site|website|page) (?:push|deliver)|SocGholish|ClearFake", re.I)),
    ("FAKE-SOFTWARE", re.compile(r"fake (?:download|installer|software|website|site|app)|typosquat", re.I)),
    ("PHISHING", re.compile(r"\bphishing\b", re.I)),
    ("PAYLOAD-HOSTING", re.compile(r"payload (?:hosting|server|delivery|url)|host(?:s|ing) the payload|"
                                   r"deliver(?:s|ing)? (?:the|a) payload", re.I)),
    ("REDIRECTOR", re.compile(r"redirectors?|redirect(?:ion|ing) (?:domain|server|url)", re.I)),
    ("MALWARE-DISTRIBUTION", re.compile(r"distribut\w+ (?:malware|the payload|infected)|malware distribution|"
                                        r"malvertis\w+|drive[- ]by|deliver\w+ (?:malware|the payload)", re.I)),
    ("APT", re.compile(r"\bAPT\d{1,3}\b|nation[- ]state|state[- ]sponsored", re.I)),
    ("MALWARE", re.compile(r"\bmalware\b|\btrojan(?:ized|ised)?\b|\bbackdoor\b|\brootkit\b|\bwiper\b", re.I)),
]

CATEGORIES_BY_PRIORITY = [
    "C2", "RANSOMWARE", "INFOSTEALER", "RAT", "LOADER", "BOTNET",
    "CRACKED-SOFTWARE", "PIRATED-SOFTWARE", "FAKE-UPDATE", "FAKE-SOFTWARE",
    "MALWARE-DISTRIBUTION", "PAYLOAD-HOSTING", "REDIRECTOR", "PHISHING",
    "APT", "MALWARE", "OTHER",
]

RELEVANCE_RE = re.compile(
    r"crack(?:ed|s|ing)?|keygen|activat(?:or|ion)|pirat(?:ed|es|y)|warez|unauthori[sz]ed software|"
    r"trojani[sz]ed|fake (?:update|download|install|captcha|website|site|browser)|fakeupdate|"
    r"loaders?|droppers?|downloaders?|stealers?|infostealer|info stealer|\bRATs?\b|botnets?|"
    r"command[\s\-]and[\s\-]control|\bC2\b|ransomware|backdoor|trojan|malware|"
    r"cobalt strike|malvertis\w+|clickfix|smokeloader|qakbot|qbot|emotet|icedid|"
    r"typosquat|extortion|keyloggers?|spyware|remote access trojan",
    re.I,
)


LEGIT_SENTENCE_RE = re.compile(
    r"\blegitimate\b|\blegit\b(?:imate)? (?:service|endpoint|domain|infrastructure|api)|"
    r"benign (?:service|endpoint|domain|api)|\bfalse positive\b|"
    r"\bnot malicious\b|compromised (?:but )?legitimate",
    re.I,
)


def category_for_family(family: str) -> str | None:
    if not family:
        return None
    f = family.strip().lower()
    if f in FAMILY_TAG_NOISE:
        return None
    if f in FAMILY_CATEGORY:
        return FAMILY_CATEGORY[f]
    for key, cat in FAMILY_CATEGORY.items():
        if key in f or f in key:
            return cat
    return "MALWARE" if len(f) >= 4 else None


def is_family_tag(tag: str) -> bool:
    t = tag.strip().lower()
    if not t or t in FAMILY_TAG_NOISE:
        return False
    return bool(t) and len(t) >= 3


def article_flags(text: str) -> dict:
    flags = {
        "explicit_c2": bool(C2_SENTENCE_RE.search(text)),
        "explicit_malware": bool(MALICIOUS_SENTENCE_RE.search(text)),
        "categories": [],
        "families": [],
    }
    seen = set()
    for cat, rx in ARTICLE_CATEGORY_PATTERNS:
        if rx.search(text) and cat not in seen:
            seen.add(cat)
            flags["categories"].append(cat)
    low = text.lower()
    for fam in FAMILY_CATEGORY:
        if len(fam) >= 5 and fam in low and fam not in flags["families"]:
            flags["families"].append(fam)
    return flags


def sentence_categories(sentence: str) -> list[str]:
    out = []
    for cat, rx in ARTICLE_CATEGORY_PATTERNS:
        if rx.search(sentence):
            out.append(cat)
    return out


def compose_threat(categories: list[str], family: str = "") -> str:
    cats = sorted(set(categories), key=lambda c: CATEGORIES_BY_PRIORITY.index(c)
                  if c in CATEGORIES_BY_PRIORITY else 99)
    labels = {
        "C2": "C2 infrastructure", "RANSOMWARE": "Ransomware", "INFOSTEALER": "Infostealer",
        "RAT": "RAT", "LOADER": "Loader/Downloader", "BOTNET": "Botnet",
        "CRACKED-SOFTWARE": "Cracked-software malware", "PIRATED-SOFTWARE": "Pirated-software malware",
        "FAKE-UPDATE": "Fake update", "FAKE-SOFTWARE": "Fake software",
        "MALWARE-DISTRIBUTION": "Malware distribution", "PAYLOAD-HOSTING": "Payload hosting",
        "REDIRECTOR": "Redirector", "PHISHING": "Phishing", "APT": "APT",
        "MALWARE": "Malware", "OTHER": "Other",
    }
    parts = [labels.get(c, c) for c in cats[:2]]
    if family:
        return f"{', '.join(parts) if parts else 'Threat'} — {family}"
    return ", ".join(parts) if parts else "Threat intelligence indicator"
