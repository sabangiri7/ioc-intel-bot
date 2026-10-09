"""IOC Intelligence Collection Bot — collects, validates, deduplicates, scores,
and exports threat-indicator IOCs (C2, malware distribution, cracked/fake software).

Safety: research/manual-review tool only. Never blocks, never calls the
CrowdStrike Falcon API, never resolves DNS, never queries internal assets.
"""
