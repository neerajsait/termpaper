import email
from email.parser import BytesParser
from email.policy import default as default_policy
import dns.resolver
import spf
import dkim
import sys
import os
import time

# ------------ Parsing helpers ------------

def get_domain_from_address(address):
    try:
        if not address:
            return None
        return address.split('@')[-1].lower().strip()
    except Exception:
        return None

def get_from_domain(msg):
    from_header = msg.get('From', '')
    try:
        addr = email.utils.parseaddr(from_header)[1]
        return get_domain_from_address(addr)
    except Exception:
        return None

def extract_dkim_domain(msg):
    try:
        dkim_headers = msg.get_all('DKIM-Signature', [])
        for header in dkim_headers:
            parts = [part.strip() for part in header.split(';')]
            for part in parts:
                if part.lower().startswith("d="):
                    return part[2:].lower()
    except Exception:
        return None
    return None

# ------------ DNS + DMARC helpers ------------

def resolve_txt_records(name, retries=5, delay=2):
    # Use reliable public resolvers
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
    my_resolver.lifetime = 15.0

    for attempt in range(retries):
        try:
            answers = my_resolver.resolve(name, 'TXT')
            recs = []
            for r in answers:
                s = ''.join([s.decode() if isinstance(s, bytes) else s for s in r.strings]).strip()
                recs.append(s)
            return recs
        except dns.resolver.Timeout:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return []
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception as e:
            print(f"DNS query error (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return []

def get_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"
    records = resolve_txt_records(dmarc_domain)
    if not records:
        # Fallback to parent domain if subdomain has no DMARC
        parent_domain = '.'.join(domain.split('.')[-2:])
        if parent_domain != domain:
            print(f"No DMARC for {domain}, trying parent: {parent_domain}")
            records = resolve_txt_records(f"_dmarc.{parent_domain}")
    for rec in records:
        if rec.lower().startswith('v=dmarc1'):
            parts = [part.strip() for part in rec.split(';') if part.strip()]
            tags = {}
            for part in parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    tags[k.lower()] = v
            return tags
    return None

def get_effective_tld_plus_one(domain):
    try:
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain.lower()
    except Exception:
        return domain.lower()

def is_aligned(domain1, domain2, strict=False):
    if not domain1 or not domain2:
        return False
    if strict:
        return domain1 == domain2
    return get_effective_tld_plus_one(domain1) == get_effective_tld_plus_one(domain2)

def check_dmarc_alignment(from_domain, dkim_domain, spf_domain, adkim='r', aspf='r'):
    strict_dkim = (adkim or 'r').lower() == 's'
    strict_spf = (aspf or 'r').lower() == 's'
    dkim_aligned = is_aligned(dkim_domain, from_domain, strict_dkim)
    spf_aligned = is_aligned(spf_domain, from_domain, strict_spf)
    return dkim_aligned or spf_aligned

# ------------ SPF / DKIM checks ------------

def spf_check(ip, mail_from, helo):
    try:
        if not isinstance(ip, str) or not isinstance(mail_from, str) or not isinstance(helo, str):
            return 'permerror', 'Invalid input types for SPF check'
        # result in {pass, fail, softfail, neutral, none, permerror, temperror}
        result, reason = spf.check2(ip, mail_from or '', helo or '')
        return result, reason
    except Exception as e:
        return 'temperror', f"SPF error: {e}"

def dkim_check(raw_email_bytes):
    try:
        if dkim.verify(raw_email_bytes):
            return 'pass', 'Valid DKIM signature'
        else:
            return 'fail', 'DKIM verification failed'
    except dkim.DKIMException as e:
        return 'permerror', f'DKIM exception: {e}'
    except Exception as e:
        return 'temperror', f'DKIM error: {e}'

# ------------ DMARC evaluation ------------

def evaluate_dmarc(msg, dkim_result, spf_result, spf_domain):
    from_domain = get_from_domain(msg)
    if not from_domain:
        return 'none', 'No From domain'

    dmarc_policy = get_dmarc_record(from_domain)
    if not dmarc_policy:
        # If no DMARC but SPF/DKIM pass, be explicit it's neutral
        if dkim_result[0] == 'pass' or spf_result[0] == 'pass':
            return 'neutral', 'No DMARC record, but authenticated via SPF/DKIM'
        return 'none', 'No DMARC record found'

    policy = dmarc_policy.get('p', 'none').lower()
    adkim = dmarc_policy.get('adkim', 'r').lower()
    aspf = dmarc_policy.get('aspf', 'r').lower()

    dkim_domain = extract_dkim_domain(msg)
    aligned = check_dmarc_alignment(from_domain, dkim_domain, spf_domain, adkim, aspf)

    dkim_pass = (dkim_result[0] == 'pass')
    spf_pass = (spf_result[0] == 'pass')

    if aligned and (dkim_pass or spf_pass):
        return 'pass', f"DMARC pass (policy={policy}, aligned)"

    if policy == 'reject':
        return 'fail', 'DMARC fail with reject policy'
    elif policy == 'quarantine':
        return 'fail', 'DMARC fail with quarantine policy'
    else:
        return 'fail', 'DMARC fail with none policy'

# ------------ Main (Day 1 minimal) ------------

def verify_sender_day1(raw_email_bytes, client_ip, smtp_mail_from=None, helo_domain=None):
    msg = BytesParser(policy=default_policy).parsebytes(raw_email_bytes)
    spf_domain = get_domain_from_address(smtp_mail_from) if smtp_mail_from else None
    from_domain = get_from_domain(msg)

    spf_res = spf_check(client_ip, smtp_mail_from or '', helo_domain or '')
    dkim_res = dkim_check(raw_email_bytes)
    dmarc_status, dmarc_detail = evaluate_dmarc(msg, dkim_res, spf_res, spf_domain)

    return {
        'from_domain': from_domain,
        'spf': {'result': spf_res[0], 'detail': spf_res[1], 'mail_from_domain': spf_domain, 'helo_domain': helo_domain, 'client_ip': client_ip},
        'dkim': {'result': dkim_res[0], 'detail': dkim_res[1]},
        'dmarc': {'result': dmarc_status, 'detail': dmarc_detail},
    }

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python app_day1.py <email_file> <client_ip> <smtp_mail_from> <helo_domain>")
        sys.exit(1)

    email_path = sys.argv[1]
    client_ip = sys.argv[2]
    mail_from = sys.argv[3] if sys.argv[3] != "-" else ""
    helo_domain = sys.argv[4] if sys.argv[4] != "-" else ""

    if not os.path.isfile(email_path):
        print(f"Email file '{email_path}' not found.")
        sys.exit(1)

    with open(email_path, 'rb') as f:
        raw_email = f.read()

    result = verify_sender_day1(raw_email, client_ip, mail_from, helo_domain)

    print(f"From Domain: {result['from_domain']}")
    print(f"SPF: {result['spf']}")
    print(f"DKIM: {result['dkim']}")
    print(f"DMARC: {result['dmarc']}")
