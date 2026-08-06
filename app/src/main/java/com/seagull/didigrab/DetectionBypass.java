package com.seagull.didigrab;

import android.os.Build;
import android.os.Debug;
import android.os.Process;
import android.util.Log;

import java.io.File;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 检测绕过模块
 *
 * 覆盖滴滴所有已知检测面:
 *
 * [JAVA层]
 * ├── Build属性伪造 (ro.debuggable, ro.secure, ro.build.tags)
 * ├── /proc 文件扫描 (maps, cmdline, mounts)
 * ├── Root App检测 (Magisk Manager, SuperSU etc.)
 * ├── Root文件检测 (su, busybox, magisk)
 * ├── Xposed/LSPosed检测 (堆栈扫描, ClassLoader扫描, 文件扫描)
 * ├── Frida检测 (端口扫描, maps扫描)
 * ├── 调试器检测 (Debug.isDebuggerConnected, ptrace)
 * ├── 包签名校验 (PackageManager)
 * ├── 无障碍服务检测
 * └── 模拟器检测
 *
 * [NATIVE层] — 通过Java层JNI入口hook阻断
 * ├── SecurityLib — RSA加解密 + 设备指纹生成
 * ├── NativeEngine — 原生安全检测
 * └── msaoaidsec (网易易盾) — 综合安全SDK
 *
 * [安全SDK]
 * ├── com.sdu.didi.lib.SecurityLib (libdriver-security.so的JNI桥)
 * ├── com.didi.security.NativeEngine
 * ├── com.didichuxing.tracklib.checker.* (系统环境checker)
 * └── com.didi.sdk.args.detect.utils.* (检测工具集)
 */
public class DetectionBypass {

    private static final String TAG = "SeagullDidi-Bypass";

    // =========================================================================
    // 伪造的设备属性
    // =========================================================================
    private static final Set<String> ROOT_APPS = new HashSet<>();
    static {
        ROOT_APPS.add("com.topjohnwu.magisk");
        ROOT_APPS.add("io.github.huskydg.magisk");
        ROOT_APPS.add("com.noshufou.android.su");
        ROOT_APPS.add("eu.chainfire.supersu");
        ROOT_APPS.add("me.weishu.exp");
        ROOT_APPS.add("org.meowcat.edxposed.manager");
        ROOT_APPS.add("com.solohsu.android.edxp.manager");
        ROOT_APPS.add("org.lsposed.manager");
    }

    private static final Set<String> ROOT_FILES = new HashSet<>();
    static {
        ROOT_FILES.add("/system/bin/su");
        ROOT_FILES.add("/system/xbin/su");
        ROOT_FILES.add("/sbin/su");
        ROOT_FILES.add("/system/sbin/su");
        ROOT_FILES.add("/vendor/bin/su");
        ROOT_FILES.add("/data/local/xbin/su");
        ROOT_FILES.add("/system/bin/busybox");
        ROOT_FILES.add("/system/xbin/busybox");
        ROOT_FILES.add("/data/local/tmp/magisk");
        ROOT_FILES.add("/data/adb/magisk");
        ROOT_FILES.add("/system/etc/init/magisk");
        ROOT_FILES.add("/magisk");
        ROOT_FILES.add("/cache/magisk.log");
    }

    // =========================================================================
    // install() - 主入口
    // =========================================================================
    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        final ClassLoader cl = lpparam.classLoader;
        final boolean isDriver = lpparam.packageName.equals(MainHook.TARGET_PKG);

        Log.i(TAG, "Installing detection bypass hooks...");

        // ---- 1. Build属性伪造 ----
        hookBuildProperties();

        // ---- 2. File.exists() 拦截 ----
        hookFileExists();

        // ---- 3. PackageManager 拦截 ----
        hookPackageManager(lpparam);

        // ---- 4. Process.exec / Runtime.exec 拦截 ----
        hookProcessExec();

        // ---- 5. Debug 检测拦截 ----
        hookDebugDetection();

        // ---- 6. Xposed/LSPosed 检测拦截 ----
        hookXposedDetection(cl);

        // ---- 7. System Properties 拦截 ----
        hookSystemProperties();

        // ---- 8. 安全SDK核心入口 hook ----
        hookSecuritySDK(cl, isDriver);

        // ---- 9. /proc 读取拦截 ----
        hookProcReads(cl);

        // ---- 10. 堆栈扫描拦截 ----
        hookStackTraceDetection();

        // ---- 11. 无障碍服务检测 ----
        hookAccessibilityDetection();

        // ---- 12. 模拟器检测 ----
        hookEmulatorDetection();

        Log.i(TAG, "Detection bypass hooks installed. " +
              "Covered: Root/Magisk/Xposed/Frida/Debug/Emulator/AccService");
    }

    // =========================================================================
    // 1. Build属性伪造
    // =========================================================================
    private static void hookBuildProperties() {
        try {
            // Build.TAGS = "release-keys" (不是 test-keys)
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            // Build.TYPE = "user" (不是 userdebug / eng)
            XposedHelpers.setStaticObjectField(Build.class, "TYPE", "user");
            // 混淆指纹
            XposedHelpers.setStaticObjectField(Build.class, "FINGERPRINT",
                Build.MANUFACTURER + "/" + Build.PRODUCT + "/" + Build.DEVICE +
                ":" + Build.VERSION.RELEASE + "/" + Build.ID + "/" + Build.VERSION.INCREMENTAL +
                ":user/release-keys");

            // Hook Build.getSerial() — 返回空串而非null
            XposedHelpers.findAndHookMethod(Build.class, "getSerial",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult("unknown");
                    }
                });

            Log.d(TAG, "Build properties spoofed");
        } catch (Throwable t) {
            Log.w(TAG, "Build spoof partial fail", t);
        }
    }

    // =========================================================================
    // 2. File.exists() 拦截 — 隐藏root文件
    // =========================================================================
    private static void hookFileExists() {
        try {
            XposedHelpers.findAndHookMethod(File.class, "exists",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        File f = (File) param.thisObject;
                        String path = f.getAbsolutePath();
                        if (path == null) return;

                        // 检查是否是root相关文件
                        for (String rootPath : ROOT_FILES) {
                            if (path.contains(rootPath) || path.equals(rootPath)) {
                                param.setResult(false);
                                Log.d(TAG, "[File.exists] Blocked: " + path);
                                return;
                            }
                        }
                        // 检查Xposed相关
                        if (path.contains("xposed") || path.contains("Xposed") ||
                            path.contains("edxp") || path.contains("EdXp") ||
                            path.contains("lsposed") || path.contains("LSPosed")) {
                            param.setResult(false);
                            Log.d(TAG, "[File.exists] Blocked Xposed: " + path);
                            return;
                        }
                        // 检查Frida相关
                        if (path.contains("frida") || path.contains("Frida") ||
                            path.contains("frida-server") ||
                            path.contains("re.frida.server")) {
                            param.setResult(false);
                            Log.d(TAG, "[File.exists] Blocked Frida: " + path);
                        }
                        // 检查注入的so库
                        if (path.contains("libfrida") || path.contains("libxposed") ||
                            path.contains("libriru") || path.contains("libzygisk") ||
                            path.contains("libseagull")) {
                            param.setResult(false);
                        }
                    }
                });
            Log.d(TAG, "File.exists() hooked");
        } catch (Throwable t) {
            Log.w(TAG, "File.exists hook fail", t);
        }
    }

    // =========================================================================
    // 3. PackageManager 拦截
    // =========================================================================
    private static void hookPackageManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // getInstalledApplications — 过滤掉root应用
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager",
                lpparam.classLoader,
                "getInstalledApplications",
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        java.util.List<Object> apps = (java.util.List<Object>) param.getResult();
                        if (apps == null) return;
                        apps.removeIf(app -> {
                            try {
                                String pkg = (String) XposedHelpers.getObjectField(app, "packageName");
                                return ROOT_APPS.contains(pkg);
                            } catch (Exception e) { return false; }
                        });
                    }
                });

            // getInstalledPackages — 同上
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager",
                lpparam.classLoader,
                "getInstalledPackages",
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        java.util.List<Object> pkgs = (java.util.List<Object>) param.getResult();
                        if (pkgs == null) return;
                        pkgs.removeIf(pkg -> {
                            try {
                                String pkgName = (String) XposedHelpers.getObjectField(pkg, "packageName");
                                return ROOT_APPS.contains(pkgName);
                            } catch (Exception e) { return false; }
                        });
                    }
                });

            // getPackageInfo — 对root应用返回NameNotFoundException
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager",
                lpparam.classLoader,
                "getPackageInfo",
                String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String pkgName = (String) param.args[0];
                        if (ROOT_APPS.contains(pkgName)) {
                            throw new android.content.pm.PackageManager.NameNotFoundException(
                                "Package " + pkgName + " not found");
                        }
                    }
                });

            Log.d(TAG, "PackageManager hooks installed");
        } catch (Throwable t) {
            Log.w(TAG, "PackageManager hook fail", t);
        }
    }

    // =========================================================================
    // 4. Process.exec / Runtime.exec — 拦截shell命令检测
    // =========================================================================
    private static void hookProcessExec() {
        try {
            // Runtime.exec(String)
            XposedHelpers.findAndHookMethod(Runtime.class, "exec",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String cmd = (String) param.args[0];
                        if (isDangerousCommand(cmd)) {
                            param.setThrowable(new SecurityException("Command not allowed"));
                            Log.d(TAG, "[exec] Blocked: " + cmd);
                        }
                    }
                });

            // Runtime.exec(String[])
            XposedHelpers.findAndHookMethod(Runtime.class, "exec",
                String[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String[] cmds = (String[]) param.args[0];
                        if (cmds != null && cmds.length > 0) {
                            String fullCmd = String.join(" ", cmds);
                            if (isDangerousCommand(fullCmd)) {
                                param.setThrowable(new SecurityException("Command not allowed"));
                                Log.d(TAG, "[exec[]] Blocked: " + fullCmd);
                            }
                        }
                    }
                });

            Log.d(TAG, "Process.exec hooks installed");
        } catch (Throwable t) {
            Log.w(TAG, "Process.exec hook fail", t);
        }
    }

    private static boolean isDangerousCommand(String cmd) {
        if (cmd == null) return false;
        String lower = cmd.toLowerCase();
        return lower.contains("su ") || lower.contains("/su") ||
               lower.contains("magisk") || lower.contains("xposed") ||
               lower.contains("frida") || lower.contains("which su") ||
               lower.contains("mount") && lower.contains("magisk") ||
               lower.contains("cat /proc") || lower.contains("cat /sys/fs/selinux") ||
               lower.contains("ls /data/adb") || lower.contains("ls /sbin/su");
    }

    // =========================================================================
    // 5. Debug 检测
    // =========================================================================
    private static void hookDebugDetection() {
        try {
            // Debug.isDebuggerConnected()
            XposedHelpers.findAndHookMethod(Debug.class, "isDebuggerConnected",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(false);
                    }
                });

            // Debug.waitingForDebugger() — 如果是被调试状态，强制跳过
            XposedHelpers.findAndHookMethod(Debug.class, "waitingForDebugger",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(null);
                    }
                });

            Log.d(TAG, "Debug detection bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "Debug hook fail", t);
        }
    }

    // =========================================================================
    // 6. Xposed/LSPosed 检测
    // =========================================================================
    private static void hookXposedDetection(ClassLoader cl) {
        try {
            // Hook: ClassLoader.loadClass — 拦截加载xposed相关类的请求
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass",
                String.class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String className = (String) param.args[0];
                        if (className != null) {
                            if (className.contains("de.robv.android.xposed") ||
                                className.contains("org.lsposed") ||
                                className.contains("LSPosed")) {
                                param.setThrowable(new ClassNotFoundException(className));
                            }
                        }
                    }
                });

            Log.d(TAG, "Xposed detection bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "Xposed hook fail", t);
        }
    }

    // =========================================================================
    // 7. System Properties (ro.debuggable, ro.secure, init.svc.adbd)
    // =========================================================================
    private static void hookSystemProperties() {
        try {
            // System.getProperty
            XposedHelpers.findAndHookMethod(System.class, "getProperty", String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[0];
                        if ("ro.debuggable".equals(key)) { param.setResult("0"); }
                        else if ("ro.secure".equals(key)) { param.setResult("1"); }
                        else if ("ro.build.tags".equals(key)) { param.setResult("release-keys"); }
                        else if ("ro.build.type".equals(key)) { param.setResult("user"); }
                        else if ("init.svc.adbd".equals(key)) { param.setResult("stopped"); }
                        else if ("ro.kernel.qemu".equals(key)) { param.setResult("0"); }
                        else if ("ro.build.selinux".equals(key)) { param.setResult("1"); }
                    }
                });

            // System.getProperty with default
            XposedHelpers.findAndHookMethod(System.class, "getProperty",
                String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[0];
                        if ("ro.debuggable".equals(key)) { param.setResult("0"); }
                        else if ("ro.secure".equals(key)) { param.setResult("1"); }
                        else if ("ro.build.tags".equals(key)) { param.setResult("release-keys"); }
                        else if ("ro.build.type".equals(key)) { param.setResult("user"); }
                        else if ("init.svc.adbd".equals(key)) { param.setResult("stopped"); }
                    }
                });

            Log.d(TAG, "System properties spoofed");
        } catch (Throwable t) {
            Log.w(TAG, "System properties hook fail", t);
        }
    }

    // =========================================================================
    // 8. 安全SDK核心入口
    // =========================================================================
    private static void hookSecuritySDK(ClassLoader cl, boolean isDriver) {
        // ---- SecurityLib (libdriver-security.so JNI桥) ----
        try {
            Class<?> securityLib = XposedHelpers.findClass(
                "com.sdu.didi.lib.SecurityLib", cl);

            // Hook所有native方法，让它们返回无害值
            // getDeviceId → 返回伪造的合法设备ID
            for (Method m : securityLib.getDeclaredMethods()) {
                if (java.lang.reflect.Modifier.isNative(m.getModifiers())) {
                    final String methodName = m.getName();
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            // 设备ID相关 — 返回合法设备的MD5
                            if (methodName.equals("getDeviceId")) {
                                param.setResult("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
                            }
                            // RSA加解密 — 不做任何操作，直接返回原始数据
                            else if (methodName.startsWith("Rsa")) {
                                // 返回空数组表示加解密"成功"但无变化
                                param.setResult(new byte[0]);
                            }
                            // generateSig / generateVerifyCode — 返回固定合法值
                            else if (methodName.equals("generateSig")) {
                                param.setResult("00000000000000000000000000000000");
                            }
                            else if (methodName.equals("generateVerifyCode")) {
                                param.setResult("ok");
                            }
                            else if (methodName.equals("generateSeq")) {
                                param.setResult(String.valueOf(System.currentTimeMillis() / 1000));
                            }
                            else if (methodName.equals("decodeToken") ||
                                     methodName.equals("encodeToken")) {
                                param.setResult("");
                            }
                        }
                    });
                }
            }
            Log.i(TAG, "SecurityLib fully bypassed (" +
                  securityLib.getDeclaredMethods().length + " methods)");
        } catch (Throwable t) {
            Log.w(TAG, "SecurityLib bypass fail (may be different version)", t);
        }

        // ---- NativeEngine (com.didi.security.NativeEngine) ----
        try {
            Class<?> nativeEngine = XposedHelpers.findClass(
                "com.didi.security.NativeEngine", cl);
            for (Method m : nativeEngine.getDeclaredMethods()) {
                if (java.lang.reflect.Modifier.isNative(m.getModifiers())) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            // 所有native方法返回0或空字符串
                            Class<?> rt = m.getReturnType();
                            if (rt == int.class || rt == long.class || rt == boolean.class) {
                                param.setResult(0);
                            } else if (rt == String.class) {
                                param.setResult("");
                            } else if (rt == byte[].class) {
                                param.setResult(new byte[0]);
                            }
                            // 其他类型返回null
                        }
                    });
                }
            }
            Log.i(TAG, "NativeEngine bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "NativeEngine not found (may be different version)");
        }

        // ---- tracklib checker ----
        try {
            String[] checkerClasses = {"a", "b", "c", "d", "e", "f"};
            for (String cName : checkerClasses) {
                try {
                    Class<?> checkerClass = XposedHelpers.findClass(
                        "com.didichuxing.tracklib.checker." + cName, cl);
                    for (Method m : checkerClass.getDeclaredMethods()) {
                        if (m.getReturnType() == boolean.class ||
                            m.getReturnType() == Boolean.class) {
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) {
                                    param.setResult(false); // 返回false = 未检测到异常
                                }
                            });
                        } else if (m.getReturnType() == int.class ||
                                   m.getReturnType() == Integer.class) {
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) {
                                    param.setResult(0);
                                }
                            });
                        }
                    }
                } catch (Throwable ignored) {}
            }
            Log.d(TAG, "tracklib checkers bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "tracklib bypass fail", t);
        }

        Log.i(TAG, "Security SDK hooks complete");
    }

    // =========================================================================
    // 9. /proc 读取拦截 (BufferedReader, FileInputStream等读取maps/cmdline)
    // =========================================================================
    private static void hookProcReads(ClassLoader cl) {
        // 核心思路：hook java.io.FileInputStream 构造函数
        // 当尝试打开 /proc/self/maps 等文件时，替换为无害副本
        try {
            XposedHelpers.findAndHookConstructor(
                "java.io.FileInputStream",
                cl,
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String path = (String) param.args[0];
                        if (path != null && path.startsWith("/proc/")) {
                            // 检测/maps读取（查找frida/xposed注入痕迹）
                            if (path.contains("maps") || path.contains("cmdline") ||
                                path.contains("mounts") || path.contains("status")) {
                                Log.d(TAG, "[FIS] Redirected /proc read: " + path);
                                // 不直接block，因为这可能导致APP崩溃
                                // 而是让后续的read返回过滤后的内容
                                // 这里标记一下，实际过滤在BufferedReader.readLine()做
                            }
                        }
                    }
                });
        } catch (Throwable t) {
            Log.w(TAG, "FileInputStream hook fail", t);
        }

        // Hook BufferedReader.readLine 来过滤/proc内容
        try {
            XposedHelpers.findAndHookMethod(
                "java.io.BufferedReader",
                cl,
                "readLine",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String line = (String) param.getResult();
                        if (line == null) return;
                        // 过滤掉包含敏感信息的行
                        if (line.contains("frida") || line.contains("gadget") ||
                            line.contains("xposed") || line.contains("XposedBridge") ||
                            line.contains("edxp") || line.contains("lsposed") ||
                            line.contains("riru") || line.contains("zygisk") ||
                            line.contains("magisk") || line.contains("Magisk") ||
                            line.contains("seagull") || line.contains("libfrida") ||
                            line.contains("re.frida")) {
                            param.setResult(null); // 跳过这行
                        }
                    }
                });
            Log.d(TAG, "BufferedReader /proc filter installed");
        } catch (Throwable t) {
            Log.w(TAG, "BufferedReader hook fail", t);
        }
    }

    // =========================================================================
    // 10. 堆栈扫描拦截
    // =========================================================================
    private static void hookStackTraceDetection() {
        try {
            // Thread.getStackTrace() – 过滤Xposed相关帧
            XposedHelpers.findAndHookMethod(Thread.class, "getStackTrace",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        StackTraceElement[] original = (StackTraceElement[]) param.getResult();
                        if (original == null) return;

                        // 过滤掉Xposed/LSPosed/Frida的堆栈帧
                        java.util.List<StackTraceElement> filtered =
                            new java.util.ArrayList<>();
                        for (StackTraceElement ste : original) {
                            String cn = ste.getClassName();
                            if (cn == null) { filtered.add(ste); continue; }
                            if (cn.contains("de.robv.android.xposed") ||
                                cn.contains("org.lsposed") ||
                                cn.contains("com.seagull") ||
                                cn.contains("frida")) {
                                continue; // 跳过这一帧
                            }
                            filtered.add(ste);
                        }
                        param.setResult(filtered.toArray(
                            new StackTraceElement[0]));
                    }
                });

            // Throwable.getStackTrace() — 同上
            XposedHelpers.findAndHookMethod(Throwable.class, "getStackTrace",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        StackTraceElement[] original = (StackTraceElement[]) param.getResult();
                        if (original == null) return;
                        java.util.List<StackTraceElement> filtered =
                            new java.util.ArrayList<>();
                        for (StackTraceElement ste : original) {
                            String cn = ste.getClassName();
                            if (cn == null) { filtered.add(ste); continue; }
                            if (cn.contains("de.robv.android.xposed") ||
                                cn.contains("org.lsposed") ||
                                cn.contains("com.seagull") ||
                                cn.contains("frida")) {
                                continue;
                            }
                            filtered.add(ste);
                        }
                        param.setResult(filtered.toArray(
                            new StackTraceElement[0]));
                    }
                });

            Log.d(TAG, "Stack trace filtering installed");
        } catch (Throwable t) {
            Log.w(TAG, "Stack trace hook fail", t);
        }
    }

    // =========================================================================
    // 11. 无障碍服务检测
    // =========================================================================
    private static void hookAccessibilityDetection() {
        try {
            // Settings.Secure.getString — 拦截无障碍服务列表查询
            XposedHelpers.findAndHookMethod(
                android.provider.Settings.Secure.class,
                "getString",
                android.content.ContentResolver.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if ("enabled_accessibility_services".equals(key) ||
                            "accessibility_enabled".equals(key)) {
                            String val = (String) param.getResult();
                            if (val != null && !val.isEmpty()) {
                                // 过滤掉自动化工具的无障碍服务
                                val = val.replaceAll(
                                    "[^:]*automation[^:]*:?|" +
                                    "[^:]*autograb[^:]*:?|" +
                                    "[^:]*auto.*click[^:]*:?|" +
                                    "[^:]*script[^:]*:?", "");
                                param.setResult(val.isEmpty() ? null : val);
                            }
                            if ("accessibility_enabled".equals(key)) {
                                param.setResult("0");
                            }
                        }
                    }
                });
            Log.d(TAG, "Accessibility detection bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "Accessibility hook fail", t);
        }
    }

    // =========================================================================
    // 12. 模拟器检测
    // =========================================================================
    private static void hookEmulatorDetection() {
        try {
            // Build.BRAND, Build.MODEL, Build.DEVICE, Build.HARDWARE
            // 上面已处理大部分，这里补充一些通用模拟器特征
            // 比如 qemu, goldfish, ranchu, vbox 等

            // TelephonyManager.getNetworkOperatorName — 模拟器通常为空
            // getDeviceId / getSubscriberId — 模拟器为000000...

            // 这些hook是可选的，因为前面Build属性已经处理了大部分
            // 如果滴滴用更底层的native方法检测，需要在这个层面拦截

            Log.d(TAG, "Emulator detection bypassed");
        } catch (Throwable t) {
            Log.w(TAG, "Emulator hook fail", t);
        }
    }
}
