from .abusech import (
    collect_feodo,
    collect_malwarebazaar,
    collect_threatfox,
    collect_urlhaus,
)
from .advisories import collect_cisa_kev
from .blocklists import collect_domain_list, collect_ip_list, collect_url_list
from .reports import collect_reports

COLLECTORS = {
    "threatfox": collect_threatfox,
    "urlhaus": collect_urlhaus,
    "feodo": collect_feodo,
    "malwarebazaar": collect_malwarebazaar,
    "cisa_kev": collect_cisa_kev,
    "ip_list": collect_ip_list,
    "domain_list": collect_domain_list,
    "url_list": collect_url_list,
    "report": collect_reports,
}
