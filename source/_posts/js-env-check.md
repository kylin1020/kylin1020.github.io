---
title: JS 环境检测点总结
date: 2024-03-18 22:34:34
tags:
    - JavaScript
    - JS逆向
---

关注开源指纹库: [fingerprintjs](https://github.com/fingerprintjs/fingerprintjs)

#### window.matchMedia
window.matchMedia() 方法用于检测当前浏览器是否支持某种 CSS 指定的媒体查询。

#### canvas指纹
相同的HTML5 Canvas元素绘制操作，在不同操作系统、不同浏览器上，产生的图片内容不完全相同。在图片格式上，不同浏览器使用了不同的图形处理引擎、不同的图片导出选项、不同的默认压缩级别等。在像素级别来看，操作系统各自使用了不同的设置和算法来进行抗锯齿和子像素渲染操作。即使相同的绘图操作，产生的图片数据的CRC检验也不相同。
示例代码如下:
```javascript
document.createElement("mycanvas");
const canvas = document.getElementById("mycanvas");
const ctx = canvas.getContext("2d");
const txt = 'qwertyuiop!@#$%^&*()_+'
ctx.textBaseline = 'top'
ctx.font = '14px \'Arial\''
ctx.textBaseline = 'tencent'
ctx.fillStyle = '#f60'
ctx.fillRect(125, 1, 62, 20)
ctx.fillStyle = '#069'
ctx.fillText(txt, 2, 15)
ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'
ctx.fillText(txt, 4, 17);
const canvasData = canvas.toDataURL();

```

#### webgl指纹
1. WebGL报告——完整的WebGL浏览器报告表是可获取、可被检测的。通过读取报告中的vendor和renderer信息，可以获取到显卡的供应商和型号信息。
2. WebGL图像——渲染和转换为哈希值的隐藏3D图像。由于最终结果取决于进行计算的硬件设备，因此此方法会为设备及其驱动程序的不同组合生成唯一值。这种方

#### ja3指纹
Ja3指纹是一种用于识别和追踪SSL/TLS加密流量的哈希值。它是通过计算客户端SSL/TLS握手期间使用的加密协议参数，包括TLS版本和密码套件等得出的。Ja3指纹的长度为32个16进制数字符（64个字符），可以用于识别加密流量的来源，例如，某个应用程序，某个操作系统，某个设备或者一个独立的网络节点。

#### 常规检测点
1. navigator.webdriver
2. navigator.platform(Win32/MacOSX/Linux)
3. navigator.userAgent
4. window._phantom
5. window.__nightmare
6. window._selenium
7. window.callPhantom
8. window.callSelenium
9. window._Selenium_IDE_Recorder
10. window.document.__webdriver_evaluate
11. window.document.__selenium_evaluate
12. window.document.__webdriver_script_function
13. window.document.__webdriver_script_func
14. window.document.__webdriver_script_fn
15. window.document.__fxdriver_evaluate
16. window.document.__driver_unwrapped
17. window.document.__webdriver_unwrapped
18. window.document.__driver_evaluate
19. window.document.__selenium_unwrapped
20. window.document.__fxdriver_unwrapped
21. window.document.documentElement.getAttribute("selenium")
22. window.document.documentElement.getAttribute("webdriver")
23. window.document.documentElement.getAttribute("driver")
