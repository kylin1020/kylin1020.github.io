---
title: 某验点选验证码分析(1)
date: 2024-04-02 09:57:55
tags:
  - 验证码破解
  - js逆向
---

链接: aHR0cHM6Ly93d3cuYmlsaWJpbGkuY29tLw==

### 流程分析

尝试点击页面的登录会触发点选验证码, 随便点几下触发验证流程.
从devtools中可以分析得到整个验证码的验证流程如下:

1. 首先访问
   https://passport.bilibili.com/x/passport-login/captcha 拿到极验的gt和challenge参数, 用于后续的验证.
   ![img_2.png](images/img_2.png)
2. 然后根据gt参数访问
   https://api.geetest.com/gettype.php 获取并加载当前版本的js代码.
   ![img_3.png](images/img_3.png)
3. 访问
   https://api.geetest.com/get.php 获取一些基本信息, 校验的服务器api地址, c, s参数等, 可以看到访问时带了一个w参数, 暂时不知道生成逻辑.
   ![img_7.png](images/img_7.png)
   ![img_6.png](images/img_6.png)
4. 访问
   https://api.geetest.com/ajax.php 接口拿到验证码校验类型, 该接口同样有w参数.
   ![img_8.png](images/img_8.png)
5. 再次访问 https://api.geetest.com/get.php , 这次请求带上了更多参数, 包括w, 验证码类型, api_server等, 返回的数据也带上了验证码图片和新的c,s参数.
   ![img_9.png](images/img_9.png)
   ![img_10.png](images/img_10.png)
6. 最后请求
   https://api.geetest.com/ajax.php 校验验证码, 主要参数是gt, challenge和w, 得到验证结果.

通过对这个流程分析发现主要参数就是w, 因此要跟踪下三个w参数的请求, 看下各自的w生成逻辑是什么.

### 第一次w生成逻辑分析
通过查看请求的调用栈可以知道第一个w是由fullpage.xxx.js生成的.
![img_11.png](images/img_11.png)
在请求调用栈上打个断点, 找下w参数在哪里生成.
![img_12.png](images/img_12.png)
可以看到代码已经经过混淆, 使用ast简单去掉字符串替换和unicode编码, override content之后继续分析.
![img_13.png](images/img_13.png)
在代码中搜索"w", 找到5处w的生成逻辑, 5处都打下断点后重新刷新.
![img_15.png](images/img_15.png)
打下断点再次刷新后停在了其中一处断点, 可以知道第一个w由i+r组成.

##### 1.1 r参数分析
r是由t["$_CCGw"]函数得到, 往下跟这个函数的逻辑.
![img_16.png](images/img_16.png)
核心代码: `new X()["encrypt"](this["$_CCHU"](e))`
其中`this["$_CCHU"]`函数如下图:
![img_17.png](images/img_17.png)
可以知道该函数作用是生成aes key, 如果已存在则使用已存在的key, 所以这个r参数应该是保存加密的aes key. 跟一下encrypt函数看下是什么加密算法.
![img_19.png](images/img_19.png)
从一些关键词判断应该是RSA算法, 返回16进制字符串, 从上下文代码中可以找到设置RSA公钥的函数SetPublic, 在该函数下断点跟一下即可知道公钥e和t.
![img_21.png](images/img_21.png)
![img_22.png](images/img_22.png)

##### 1.2 i参数分析
根据上文的代码截图可以知道i的来源.
关键代码:
```text
o = $_BFo()["encrypt1"](de["stringify"](t["$_EJV"]), t["$_CCHU"]()),
i = p["$_HEt"](o)
```
**o参数生成**  
t["$_EJV"]是一个Object, 保存了一些验证码的信息.
![img_25.png](images/img_25.png)

`t["$_CCHU"]()`从上面的i参数知道是一个aes key.  
![img_24.png](images/img_24.png)

然后分析下encrypt1函数的逻辑, 简单查看代码逻辑后基本断定是aes加密算法而且从各种函数关键词来看基本不会是魔改aes. 主动调用该函数确认是标准的aes, 并且采用cbc模式/pkcs7填充, iv默认是0000000000000000.
![img_27.png](images/img_27.png)
![img_28.png](images/img_28.png)
完成aes加密之后对每个32位的数字做如下转换
![img_29.png](images/img_29.png)
其作用是将32位的数字转为四个8位的数字  
**i参数生成**  
![img_30.png](images/img_30.png)
![img_31.png](images/img_31.png)
i由`p["$_HEt"]`函数输入o经过一系列操作之后由res+end组成, 其中`$_HCK`函数有多处将三个8bit数字换算成24bit数字然后转换为四个字符的逻辑, 似乎是base64算法变体.
t函数是取指定t二进制位上对应的值组合成新的数字.
![img.png](images/img40.png)
`$_GJI`函数作用是取对应数字的字符, 取不到则用"."代替. $_GAp="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()",
与标准base64需要的字符串差异在最后两个字符由"+/"变为了"()".
![img.png](images/img41.png)

$_GCK=7274496(二进制: 11011110000000000000000),   
$_GDu=9483264(100100001011010000000000)  
$_GEk=19220(100101100010100), $_GFY=235(11101011)    
实现标准base64需要的四个数字应该是:
0xfc0000(111111000000000000000000),  
0x3f000(111111000000000000),  
0xfc0(111111000000),  
0x3f(111111),  
跟标准base64实现有点不同.

##### 1.3 总结分析
r参数保存aes密钥, 采用RSA加密后取16进制, i是aes加密数据后采用base64编码的字符串.


### 第二次w生成逻辑分析
第二个w同样是由fullpage.xxx.js生成的.
![img.png](images/img43.png)

`n["w"] = t["$_CEAN"]`

![img.png](images/img44.png)
![img.png](images/img45.png)

跟踪下t["$_CEAN"]的生成, 可以发现同样是采用aes加密, 不过加密的数据不同, 这个r参数当中有很多未知的参数, 似乎是一些环境检测的参数.
```json
{
    "lang": "zh-cn",
    "type": "fullpage",
    "tt": "M6(*((1Sj((sM((",
    "light": -1,
    "s": "c7c3e21112fe4f741921cb3e4ff9f7cb",
    "h": "321f9af1e098233dbd03f250fd2b5e21",
    "hh": "39bd9cad9e425c3a8f51610fd506e3b3",
    "hi": "09eb21b3ae9542a9bc1e8b63b3d9a467",
    "vip_order": -1,
    "ct": -1,
    "ep": {
        "v": "9.1.9-r8k4eq",
        "te": false,
        "$_BBp": false,
        "ven": "Google Inc. (NVIDIA)",
        "ren": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 (0x00002488) Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "fp": null,
        "lp": null,
        "em": {
            "ph": 0,
            "cp": 0,
            "ek": "11",
            "wd": 1,
            "nt": 0,
            "si": 0,
            "sc": 0
        },
        "tm": {
            "a": 1711849377534,
            "b": 1711849377617,
            "c": 1711849377617,
            "d": 0,
            "e": 0,
            "f": 1711849377539,
            "g": 1711849377539,
            "h": 1711849377539,
            "i": 1711849377539,
            "j": 1711849377539,
            "k": 0,
            "l": 1711849377547,
            "m": 1711849377614,
            "n": 1711849377615,
            "o": 1711849377620,
            "p": 1711849377751,
            "q": 1711849377751,
            "r": 1711849377752,
            "s": 1711849378121,
            "t": 1711849378121,
            "u": 1711849378121
        },
        "dnf": "dnf",
        "by": 2
    },
    "passtime": 8258,
    "rp": "d2d182b3ce6cf55f590e9ec11c9b1635",
    "captcha_token": "549902629",
    "otpj": "jm4jwcx7"
}
```
搜一下其中关键词例如"hh"找到代码逻辑位置.
![img.png](images/img46.png)

##### 2.1 s参数分析
![img.png](images/img49.png)
![img.png](images/img51.png)
关键代码`H(p["$_HD_"](t))`, 其中p["$_HD_"]根据上文分析已知是base64变体算法, t是一个加密的字符串, H函数是标准md5算法.
![img.png](images/20240331123103.png)
![img.png](images/20240331123147.png)
`$_BICT`函数用于收集鼠标操作事件并采用base64编码, base64字符映射为"()*,-./0123456789:?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~".
收集到的鼠标事件信息会进行一系列转换成二进制字符串后进行base64编码, 核心代码如下:
```text
for (var t = [], n = [], r = [], o = [], i = 0, s = e["length"]; i < s; i += 1) {
   var a = e[i],
       _ = a["length"];
   t["push"](a[0]), n["push"](2 === _ ? a[1] : a[2]), 3 === _ && (r["push"](a[1][0]), o["push"](a[1][1]));
}
var c = f(t) + d(n, !1) + d(r, !0) + d(o, !0),
   l = c["length"];
```
其中t是鼠标事件数组, 例如: ["move", "move", "down", "move", "up"], 鼠标事件包括: move/down/up/scroll/focus/blur/unload.  
n是鼠标事件发生的毫秒级时间戳数组(例如: [1711952404794, 1711952404794, 1711952404798, 1711952404798, 1711952404798]).  
如果传入该函数的e参数每个元素是一个长度3的数组, 即每个元素只记录了[事件类型, [x坐标, y坐标], 毫秒级时间戳]信息,例如: [["move", [123, 456], 1711952404794], ["down", [123, 456], 1711952404798]], 则r和o参数分别是记录x和y坐标的数组.

##### 2.2 h参数分析
```text
 n = i["$_BJDB"]["$_BICT"]();
 ["h", H(p["$_HD_"](n))];
```
![img.png](images/20240401160100.png)
`i["$_BJDB"]["$_BICT"]`函数作用是检测一个Object对象(该对象为空Object)指定名字的属性是否存在, 存在则返回该属性的值, 不存在则返回-1, 由此组成一个数组并用"magic data"字符串joi拼接这个数组得到. 检测的属性列表如下:
```json
["textLength","HTMLLength","documentMode","A","ARTICLE","ASIDE","AUDIO","BASE","BUTTON","CANVAS","CODE","IFRAME","IMG","INPUT","LABEL","LINK","NAV","OBJECT","OL","PICTURE","PRE","SECTION","SELECT","SOURCE","SPAN","STYLE","TABLE","TEXTAREA","VIDEO","screenLeft","screenTop","screenAvailLeft","screenAvailTop","innerWidth","innerHeight","outerWidth","outerHeight","browserLanguage","browserLanguages","systemLanguage","devicePixelRatio","colorDepth","userAgent","cookieEnabled","netEnabled","screenWidth","screenHeight","screenAvailWidth","screenAvailHeight","localStorageEnabled","sessionStorageEnabled","indexedDBEnabled","CPUClass","platform","doNotTrack","timezone","canvas2DFP","canvas3DFP","plugins","maxTouchPoints","flashEnabled","javaEnabled","hardwareConcurrency","jsFonts","timestamp","performanceTiming","internalip","mediaDevices","DIV","P","UL","LI","SCRIPT","touchEvent"]
```

##### 2.3 hh参数分析
```text
["hh", H(n)]
```
hh参数是n的md5值, 跟h参数区别是h参数是base64编码n之后取md5值.

##### 2.4 hi参数分析
```text
var e = t["$_BJDB"]["$_BIBg"]();
t["$_CCFY"] = e;

["hi", H(i["$_CCFY"])]
```
![img.png](images/20240401162654.png)
`t["$_BJDB"]["$_BIBg"]`函数的作用与第二点h参数中的n变量的生成相似, 只是组成的数组用"!!"字符串join拼接得到.

##### 2.5 ep参数分析
```text
["ep", i["$_CEDy"]() || -1]
```
![img.png](images/20240401164156.png)
![img.png](images/20240401165401.png)
ep参数应该是一些环境检测的汇总数据, 各属性可以在代码中看出来, 汇总如下:

| 属性名                                                                             | 作用                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 
|---------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| v                                                                               | 版本号, 当前版本为9.1.9-r8k4eq                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| te                                                                              | 是否支持touchEvent                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| $_BBp                                                                           | 是否支持mouseEvent事件                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ven                                                                             | WEBGL_debug_renderer_info扩展的UNMASKED_VENDOR_WEBGL                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ren                                                                             | WEBGL_debug_renderer_info扩展的UNMASKED_RENDERER_WEBGL                                                                                                                                                                                                                                                                                                                                                                                                                     |
| fp                                                                              | null, 可能是记录第一个鼠标事件                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| lp                                                                              | null, 可能是记录最后一个鼠标事件                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| em                                                                              | 用于检测运行环境中的各种属性, 一般1为表示有该属性, 0表示没有. 其中ph表示_phantom是否在window中; cp表示callPhantom是否在window属性中; ek表示遍历一个TypeError对象的属性列表, 检测的属性列表为["line","column","lineNumber","columnNumber","fileName","message","number","description","sourceURL","stack"], 并用一个二进制数表示, 存在则为1, 否则为0, 例如0000010001, 然后将该二进制数用16进制字符串表示, 例如"11"; wd表示webdriver在window属性中且webdriver为true, nt表示__nightmare是否在window属性中; si表示_webdriverscriptfn是否在document属性中; sc表示$cdc_asdjflasutopfhvcZLmcfl_是否在document属性中 |
| tm                                                                              | 记录window.performance.timing对象的各属性, a: navigationStart, b: unloadEventStart, c: unloadEventEnd, d: redirectStart, e: redirectEnd, f: fetchStart, g: domainLookupStart, h: domainLookupEnd, i: connectStart, j: connectEnd, k: secureConnectionStart, l: requestStart, m: responseStart, n: responseEnd, o: domLoading, p: domInteractive, q: domContentLoadedEventStart,r: domContentLoadedEventEnd, s: domComplete, t: loadEventStart, u: loadEventEnd                  |

##### 2.6 captcha_token分析
![img.png](images/20240402094301.png)
![img.png](images/20240402094622.png)
captcha_token是一个校验值, 分别对n函数, o函数和e变量计算djb hash得到, 其中n函数是计算captcha_token所处的函数, o函数是计算djb hash的函数, e是一个固定值, 如果发现程序进入到开始计算djb hash的过程中执行时间大于100ms则将e变更为"qwe".

