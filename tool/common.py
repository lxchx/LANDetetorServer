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


def make_response(obj):
    return {"msg": "成功", "data": obj}


def detect(flags, ips, func):
    print("detect Start")
    flags['is_detecting'] = True
    sapi = scamperApi()
    while flags['should_detect']:
        func(sapi.tracert(ips))
    flags['is_detecting'] = False
    print("detect End")