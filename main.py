from typing import Optional, List

from fastapi import BackgroundTasks, FastAPI, Query
from pydantic import BaseModel

import uvicorn

import requests

import json

from config import *
from tool.common import *
from tool.scamperApi import *

# 和后台探测服务共享的数据
host = ''
flags = {'should_detect': False, 'is_detecting': False}
detecors = list()

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get(root_route + "/detector_conn")
def read_detector_conn(host_addr: str, detector_ip: List[int] = Query(None)):
    host = host_addr
    if detector_ip is not None:
        for ip in detector_ip:
            detecors.append(int_ip(ip))

    return make_response(None)


@app.get(root_route + "/detector_update")
def read_detector_update(old: int, new: int):
    print("old: " + int_ip(old))
    print("new: " + int_ip(new))
    if old >= 0:
        detecors.remove(int_ip(old))
    detecors.append(int_ip(new))
    print(detecors)
    return make_response(None)


# 拿到追踪结果后如何处理
def send_to_host(res):
    # r = requests.post(int_ip(host) + '/api/edge_upload', json=res)
    edges = []
    print(json.dumps(res))
    for detect_item in res:
        tsrc = ip_int(detect_item['src'])
        tstime = detect_item['start']['sec'] * 10**6 + detect_item['start'][
            'usec']
        hops = detect_item['hops']

        for hop in hops:
            edge = {}
            edge['from'] = tsrc
            edge['to'] = ip_int(hop['addr'])
            edge['ctime'] = hop['tx']['sec']
            edge['delay'] = edge['ctime'] * 10**6 + hop['tx']['usec'] - tstime
            edge['delay'] /= 10**3
            edge['delay'] = int(edge['delay'])

            edges.append(edge)

            tsrc = ip_int(hop['addr'])
            tstime = edge['ctime'] * 10**6 + hop['tx']['usec']

        edges.append({
            'from': tsrc,
            'to': ip_int(detect_item['dst']),
            'delay': -1,
            'ctime': int(str(tstime)[:-6])  #截断微秒部分
        })
    print(json.dumps(edges))
    try:
        for e in edges:
            r = requests.post(host + '/api/edge_upload', json=json.dumps(e))
    except:
        print('边向管理程序传输失败')


@app.get(root_route + "/detect")
def read_detect(start_flag: int, background_tasks: BackgroundTasks):
    if start_flag == 1 and not flags['is_detecting']: # 保证单例运行
        flags['should_detect'] = True
        background_tasks.add_task(detect, flags, detecors, send_to_host) #添加后台任务，还有一个结果回调
    elif start_flag == 0:
        flags['should_detect'] = False
    return make_response(None)


if __name__ == '__main__':
    uvicorn.run(app='main:app',
                host="127.0.0.1",
                port=8000,
                reload=True,
                debug=True)
