---
title: Frida查找Native函数地址和所属SO模块的方法
date: 2024-03-18 11:53:19
tags:
  - frida
  - 逆向
---


### 1. Frida hook RegisterNatives
动态注册的Native函数, 一般会调用RegisterNatives来注册Native函数.  
参考: https://github.com/lasting-yang/frida_hook_libart
从libart.so中查找RegisterNatives函数的指针地址, 然后使用 Interceptor.attach 来hook.
```javascript
function find_RegisterNatives(params) {
    let symbols = Module.enumerateSymbolsSync("libart.so");
    let addrRegisterNatives = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        
        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 && 
                symbol.name.indexOf("RegisterNatives") >= 0 && 
                symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
            hook_RegisterNatives(addrRegisterNatives)
        }
    }

}

function hook_RegisterNatives(addrRegisterNatives) {

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                console.log("[RegisterNatives] method_count:", args[3]);
                let java_class = args[1];
                let class_name = Java.vm.tryGetEnv().getClassName(java_class);
                //console.log(class_name);

                let methods_ptr = ptr(args[2]);

                let method_count = parseInt(args[3]);
                for (let i = 0; i < method_count; i++) {
                    let name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    let sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    let fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                    let name = Memory.readCString(name_ptr);
                    let sig = Memory.readCString(sig_ptr);
                    let symbol = DebugSymbol.fromAddress(fnPtr_ptr)
                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr,  " fnOffset:", symbol, " callee:", DebugSymbol.fromAddress(this.returnAddress));
                }
            }
        });
    }
}

setImmediate(find_RegisterNatives);
```

#### 2. Frida获取指定方法的ArtMethod结构体地址后查找偏移
查看frida源码得知对于某个类的某个函数(例如android/os/Process::getElapsedCpuTime, 有Java.use("android/os/Process").getElapsedCpuTime.handle), 都有一个handle属性, 该属性是通过env->GetStaticMethodID或者env->GetMethodID获取,
在aosp中该methodID为ArtMethod结构体指针, 该结构体中的entry_point_from_jni_属性是该方法的入口指针地址, 根据该指针地址可以得到所属SO模块和在SO模块中的偏移.
由于AOSP每个版本的ArtMethod结构体entry_point_from_jni_属性偏移可能不同, 因此需要通过计算得到, 思路是查找一个已知Native方法是由哪个SO模块中的某个方法实现的, 然后计算其在SO模块中的偏移, 代码参考自frida-java-bridge的_getArtMethodSpec方法: https://github.com/frida/frida-java-bridge/blob/1e23abb71fd26726d59627e4da3ad8e10ba849aa/lib/android.js#L973

```typescript
function getJNICodeOffset() {
    const env = Java.vm.getEnv();
    const process = env.findClass("android/os/Process");
    const getElapsedCpuTime = env.getStaticMethodId(process, "getElapsedCpuTime", "()J");
    env.deleteLocalRef(process);

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    let jniCodeOffset = -1;
    for (let offset = 0; offset !== 64; offset += 4) {
        const field = getElapsedCpuTime.add(offset);
        const address = field.readPointer();
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          break;
        }
    }

    return jniCodeOffset;
}
```
拿到偏移后可得到所属SO模块, 示例代码如下
```typescript
function getMethodModule(method) {
    const handle = method.handle;
    const jni_code_offset = getJNICodeOffset();
    const entry = ptr(handle).add(jni_code_offset).readPointer();
    const module = Process.findModuleByAddress(entry);
    const offset = entry.sub(module?.base || 0);
    console.log(`module: ${module?.name}, entry: 0x${entry.toString(16)}, offset: 0x${offset.toString(16)}`);
    return [
        module,
        entry,
        offset
    ];
}

Java.perform(() => {
    getMethodModule(Java.use("com.meituan.android.common.mtguard.ShellBridge").main);
});
```