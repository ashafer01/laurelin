def domainToDC(domain):
    return ','.join(['dc='+dc for dc in domain.split('.')])

def dcToDomain(dcdn):
    return '.'.join([dc.split('=',1)[1] for dc in dcdn.split(',')])
