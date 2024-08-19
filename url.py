import whois

def who_is(url):
    url = url.strip()
    domain = whois.whois(url)
    
    domain_info = [
        domain.domain_name,
        domain.registrar,
        domain.name_servers
    ]

    return domain_info