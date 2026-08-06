# DiDi Driver Xposed Module — 检测绕过 + 自动抢预约单

## 功能

| 模块 | 说明 |
|------|------|
| **检测绕过** | 绕过滴滴车主的Root/Magisk/LSPosed/Frida/调试器/模拟器/无障碍服务检测 |
| **自动抢单** | 订单到达→金额过滤→人手延迟→自动触发抢单 |
| **人手模拟** | 随机反应时间、偶尔犹豫、连续上限、抢后冷却 |

## 目标APP

- `com.sdu.didi.gsui` (滴滴车主)
- 也兼容 `com.sdu.didi.psnger` (滴滴出行乘客端)

## 前置条件

- **LSPosed** (推荐) 或 EdXposed
- Magisk/KernelSU + ZygiskNext (如果需要隐藏root)
- 小米手机/其他Android 8+

## 快速开始

### 1. 编译

```bash
cd didi_grab_module
chmod +x build.sh
./build.sh          # 编译release
# 或
./build.sh debug    # 编译debug（含更多日志）
```

编译产物: `app/build/outputs/apk/release/app-release-unsigned.apk`

### 2. 安装

```bash
adb install app/build/outputs/apk/release/app-release-unsigned.apk
```

### 3. 激活 (LSPosed)

1. 打开 **LSPosed Manager**
2. 进入 **模块**
3. 启用 **DiDi Grab**
4. 点击模块 → **勾选作用域**
5. 勾选 `com.sdu.didi.gsui` (滴滴车主)
6. 返回主页面，右上角 **重启系统框架** (或直接重启手机)

### 4. 验证

```bash
# 查看日志
adb logcat -s SeagullDidi:*

# 应看到:
# SeagullDidi: [Seagull] DiDi Driver detected
# SeagullDidi-Bypass: Installing detection bypass hooks...
# SeagullDidi-Bypass: SecurityLib fully bypassed
# SeagullDidi-Grab: Installing order grab hooks...
```

### 5. 配置金额阈值

模块加载时默认 `MIN_PRICE=0`（抢所有单）。如需修改：

1. 修改 `OrderGrabber.java` 中的 `MIN_PRICE` 字段
2. 重新编译安装
3. 或在LSPosed模块设置中添加SharedPreferences支持（TODO）

## 检测绕过覆盖表

| 检测面 | 方式 | 状态 |
|--------|------|:----:|
| Root检测 (su/busybox/magisk文件) | File.exists() 拦截 | ✅ |
| Root App检测 (Magisk Manager等) | PackageManager 拦截 | ✅ |
| Build属性 (ro.debuggable等) | 静态字段覆写 + System.getProperty hook | ✅ |
| /proc/maps 扫描 | BufferedReader.readLine() 过滤 | ✅ |
| Xposed堆栈检测 | Thread/Throwable.getStackTrace() 过滤 | ✅ |
| Frida端口/进程检测 | File.exists + exec拦截 | ✅ |
| 调试器检测 | Debug.isDebuggerConnected → false | ✅ |
| 无障碍服务检测 | Settings.Secure 过滤 | ✅ |
| 模拟器检测 | Build属性伪造 | ✅ |
| SecurityLib (libdriver-security.so) | 所有native方法返回值伪造 | ✅ |
| NativeEngine (com.didi.security) | 所有native方法拦截 | ✅ |
| tracklib checker | 所有布尔方法→false | ✅ |
| 包签名校验 | 不触发 (不修改APK) | ✅ |

## 抢单逻辑

```
订单到达 (Push/UI/数据模型hook)
    ↓
提取金额 (反射遍历价格字段 + 正则解析)
    ↓
金额 >= 阈值? ────No──→ 忽略
    ↓ Yes
冷却中? ────Yes──→ 跳过
    ↓ No
连续超上限? ────Yes──→ 强制休息45-90秒
    ↓ No
人手延迟 80-400ms (15%概率犹豫加倍)
    ↓
执行抢单:
  Method 1: AssistantActionExecutor.excActionWithGrabOrder()
  Method 2: GrabOrderButton.performClick()
    ↓
记录抢单 + 随机冷却2-8秒
```

## 风险说明

⚠️ **可能被封号的情况**:
- 连续24小时不间断抢单
- 抢单速度异常快 (毫秒级)
- 抢单后从不实际出车
- 与其他自动化工具同时使用

🛡️ **降低风险**:
- 模块内置人手模拟 (随机延迟+犹豫+冷却+连续上限)
- 建议配合KernelSU + Shamiko隐藏LSPosed本身
- 不要同时使用其他hook框架 (Frida/Substrate)
- 保持正常出车行为

## 故障排查

### 模块未激活
```bash
# 检查LSPosed日志
adb logcat | grep -i lsposed
# 检查模块是否被加载
adb logcat | grep SeagullDidi
```

### 检测未绕过
```bash
# 确认模块hook已安装
adb logcat -s SeagullDidi-Bypass:D
# 如果看到 "fail" 或 "not found"，可能是APP版本更新导致类名变化
```

### 未自动抢单
```bash
# 查看抢单模块日志
adb logcat -s SeagullDidi-Grab:D
# 确认是否有 "NEW ORDER CREATED" 日志
# 检查金额提取是否正确 ("Price: ¥xxx")
```

## 适配其他版本

如果滴滴APP更新，类名可能变化。需要更新的地方:

1. `DetectionBypass.hookSecuritySDK()` — SecurityLib/NativeEngine 类路径
2. `OrderGrabber.hookGrabOrderButton()` — GrabOrderButton 类路径
3. `OrderGrabber.hookBroadOrderData()` — BaseBroadOrder 类路径
4. `OrderGrabber.hookAssistantAction()` — AssistantActionExecutor 类路径

可以通过以下命令快速找新类名:
```bash
# 解包新APK
unzip didi.apk -d unpacked/
# 搜索关键类
strings unpacked/classes*.dex | grep -E "GrabOrder|SecurityLib|BaseBroadOrder|AssistantAction"
```
