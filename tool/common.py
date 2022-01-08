from .scamperApi import scamperApi


def int_ip(num):
    s = []
    for i in range(4):
        s.append(str(num % 256))
        num //= 256
    return '.'.join(s[::-1])


def ip_int(ip):
    res = 0
    for j, i in enumerate(ip.split('.')[::-1]):
        res += 256**j * int(i)
    return res

def ip_seg_ips(segment):
    ip_seg, ip_band = segment.split('/', maxsplit=1)
    ip_band=int(ip_band)
    ip_seg=ip_int(ip_seg)
    ips=list()
    for i in range(ip_band+1):
        ip_str=int_ip(ip_seg+i)
        ips.append(ip_str)
    return ips

def make_response(obj):
    return {"msg": "成功", "data": obj}


def detect(flags, detectors, func):
    print("detect Start")
    flags['is_detecting'] = True
    sapi = scamperApi()
    ips=list()
    for ip in detectors:
        if '/' in ip:
            ips.extend(ip_seg_ips(ip))
        else:
            ips.append(ip)
    while flags['should_detect']:
        func(sapi.tracert(ips))
    flags['is_detecting'] = False
    print("detect End")