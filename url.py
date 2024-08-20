import whois

def who_is(url):
    url = url.strip()
    domain = whois.whois(url)
    return domain
