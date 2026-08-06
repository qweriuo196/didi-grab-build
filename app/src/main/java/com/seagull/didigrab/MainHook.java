package com.seagull.didigrab;

import android.os.Build;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * DiDi Driver Xposed Module — 检测绕过 + 自动抢预约单
 *
 * 目标包: com.sdu.didi.gsui (滴滴车主)
 *
 * 威胁建模:
 *   DiDi检测面分三层:
 *   1. Java层 — SecurityLib/SecurityUtil/NativeEngine + tracklib checker
 *   2. Native层 — libdriver-security.so (网易易盾) + libmsaoaidsec.so
 *   3. 服务端 — 行为建模 + 心跳异常检测
 *
 * 本模块处理第1、2层，第3层通过人手模拟降低风险。
 */
public class MainHook implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    private static final String TAG = "SeagullDidi";
    public static final String TARGET_PKG = "com.sdu.didi.gsui";
    public static final String TARGET_PKG_PSNGR = "com.sdu.didi.psnger";

    // 模块启动时间戳，用于uptime等伪造
    public static long MODULE_LOAD_TIME = System.currentTimeMillis();

    @Override
    public void initZygote(StartupParam param) {
        // Zygote阶段：全局性检测绕过（影响所有进程，但只在目标包内激活）
        // Build属性伪造 - 在system_properties读取层面拦截
        // 注意：只在Zygote阶段能hook到一些底层类
        Log.i(TAG, "[Zygote] Module loaded, API version: " + param.apiVersion);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // 只在滴滴相关包内激活
        if (!lpparam.packageName.equals(TARGET_PKG) &&
            !lpparam.packageName.equals(TARGET_PKG_PSNGR)) {
            return;
        }

        final boolean isDriver = lpparam.packageName.equals(TARGET_PKG);
        Log.i(TAG, "========================================");
        Log.i(TAG, "[Seagull] DiDi " + (isDriver ? "Driver" : "Passenger") + " detected");
        Log.i(TAG, "[Seagull] Package: " + lpparam.packageName);
        Log.i(TAG, "[Seagull] Process: " + lpparam.processName);
        Log.i(TAG, "[Seagull] Starting hook injection...");
        Log.i(TAG, "========================================");

        try {
            // =================================================================
            // Phase 1: 检测绕过 — 必须在APP初始化之前完成
            // =================================================================
            DetectionBypass.install(lpparam);

            // =================================================================
            // Phase 2: 自动抢单 — 只在主进程且是车主APP时激活
            // =================================================================
            if (isDriver && lpparam.processName.equals(TARGET_PKG)) {
                OrderGrabber.install(lpparam);
            }

            Log.i(TAG, "[Seagull] All hooks installed successfully for " + lpparam.packageName);
        } catch (Throwable t) {
            Log.e(TAG, "[Seagull] Hook installation failed", t);
        }
    }
}
