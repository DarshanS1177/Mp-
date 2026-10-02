from __future__ import annotations

import re
from urllib.parse import urlparse

FEATURE_COLUMNS = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain',
    'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port',
    'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
    'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
    'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord',
    'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

SHORTENER_HOSTS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'tiny.cc', 'rb.gy', 'rebrand.ly'
}


def _flag(is_suspicious: bool, *, neutral: bool = False) -> int:
    if is_suspicious:
        return 1
    if neutral:
        return 0
    return -1


def _normalize_url(url: str) -> str:
    value = (url or '').strip()
    if not value:
        return ''
    if '://' not in value:
        value = f'https://{value}'
    return value


def main(url: str):
    value = _normalize_url(url)
    if not value:
        return [0] * len(FEATURE_COLUMNS)

    parsed = urlparse(value)
    domain = (parsed.netloc or parsed.path or '').lower().replace('www.', '')
    host = parsed.hostname or domain
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme.lower()

    subdomains = host.split('.') if host else []
    hosting_domain = host.split('.')[-2] if len(host.split('.')) > 1 else host

    features = {
        'having_IP_Address': _flag(bool(re.search(r"^(\d{1,3}\.){3}\d{1,3}$", host or ''))),
        'URL_Length': _flag(len(value) > 75, neutral=(30 <= len(value) <= 75)),
        'Shortining_Service': _flag(any(domain.endswith(s) or s in domain for s in SHORTENER_HOSTS)),
        'having_At_Symbol': _flag('@' in value),
        'double_slash_redirecting': _flag('//' in value[value.find('://') + 3:]),
        'Prefix_Suffix': _flag('-' in (host.split('.')[0] if host else '')),
        'having_Sub_Domain': (
            1 if len(subdomains) > 2 else 0 if len(subdomains) == 2 else -1
        ),
        'SSLfinal_State': _flag(scheme != 'https'),
        'Domain_registeration_length': _flag(len(subdomains) > 3),
        'Favicon': _flag('favicon' in path.lower() or 'favicon' in query.lower()),
        'port': _flag(':' in host and host.rsplit(':', 1)[-1].isdigit()),
        'HTTPS_token': _flag('https' in host.lower()),
        'Request_URL': _flag('//' in path or '%2f%2f' in value.lower()),
        'URL_of_Anchor': _flag('javascript:' in value.lower() or 'data:' in value.lower()),
        'Links_in_tags': _flag('//' in value and value.count('//') > 1),
        'SFH': _flag('mail' in value.lower() or 'mailto:' in value.lower()),
        'Submitting_to_email': _flag('mail' in value.lower() or 'mailto:' in value.lower()),
        'Abnormal_URL': _flag('about:blank' in value.lower() or 'javascript:void' in value.lower()),
        'Redirect': _flag('redirect' in value.lower() or 'redirect=' in value.lower()),
        'on_mouseover': _flag('mouseover' in value.lower() or 'onmouseover' in value.lower()),
        'RightClick': _flag('rightclick' in value.lower() or 'contextmenu' in value.lower()),
        'popUpWidnow': _flag('alert(' in value.lower() or 'window.open' in value.lower()),
        'Iframe': _flag('iframe' in value.lower()),
        'age_of_domain': _flag(re.search(r"\d{4,}", host or '') is not None and len(subdomains) <= 2),
        'DNSRecord': _flag('norecord' in value.lower() or ('dns' in value.lower() and 'lookup' in value.lower())),
        'web_traffic': _flag('traffic' in value.lower() or 'site:' in value.lower(), neutral=True),
        'Page_Rank': _flag('google.com' not in value.lower() and 'google' in value.lower(), neutral=False),
        'Google_Index': _flag('google_index' in value.lower() or 'index:' in value.lower()),
        'Links_pointing_to_page': _flag(('link' in value.lower() and 'page' in value.lower()) or 'href=' in value.lower()),
        'Statistical_report': _flag('statistical' in value.lower() or 'report' in value.lower()),
    }

    return [features[col] for col in FEATURE_COLUMNS]
