import subprocess
import json
from copy import copy


class scamperApi:
    # 获取路由追踪结果，很慢
    def tracert(self, ips):
        command = ['scamper', '-i']
        command.extend([ip for ip in ips])
        command.extend(['-O', 'json'])

        ret = subprocess.run(command, stdout=subprocess.PIPE)
        result_str = str(ret.stdout, encoding="utf8")

        traces_data = []
        for line in result_str.split('\n'):
            if line == '':
                continue
            result_json = json.loads(line)
            if result_json['type'] == 'trace':
                traces_data.append(copy(result_json))

        return traces_data


if __name__ == "__main__":
    sapi = scamperApi()

    print(sapi.tracert(set(['113.54.245.211', '113.54.245.212'])))
