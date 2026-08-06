package com.seagull.didigrab;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;

import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 自动抢单模块
 *
 * 策略:
 *  1. Hook订单推送/数据更新链路，检测新订单到达
 *  2. 从订单数据中提取金额，与阈值比较
 *  3. 金额达标 → 人手模拟延迟 → 自动触发抢单
 *  4. 抢单成功 → 冷却计时 → 恢复监控
 *
 * 人手模拟要素:
 *  - 看到订单后的反应时间: 80-450ms (随机)
 *  - 连续抢单间隔: 2-8秒 (随机)
 *  - 偶尔"犹豫": 15%概率延迟加倍
 *  - 连续上限: 抢8单后强制休息45-90秒
 */
public class OrderGrabber {

    private static final String TAG = "SeagullDidi-Grab";

    // =========================================================================
    // 可配置参数
    // =========================================================================
    private static float MIN_PRICE = 0f;           // 最低金额阈值(元), 0=不限制
    private static boolean GRAB_ENABLED = true;    // 总开关
    private static int MAX_CONSECUTIVE = 8;        // 连续抢单上限
    private static int REST_MIN_SEC = 45;          // 最短休息时间
    private static int REST_MAX_SEC = 90;          // 最长休息时间

    // =========================================================================
    // 运行时状态
    // =========================================================================
    private static final Random RNG = new Random();
    private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());
    private static long lastGrabTime = 0;
    private static long consecutiveGrabs = 0;
    private static long restUntil = 0;
    private static long totalGrabs = 0;
    private static float lastGrabPrice = 0;
    private static WeakReference<Object> lastOrderData = null;

    // 金额正则: ¥25.00 / ￥30.5 / 45.0元 / 预估25.00
    private static final Pattern PRICE_PATTERN = Pattern.compile(
        "[¥￥]?\\s*(\\d+(?:\\.\\d{1,2})?)\\s*(?:元|¥|￥)?");

    // 过滤key: 预约单通常含这些关键词
    private static final String[] BOOKING_KEYS = {
        "预约", "预约单", "预订", "预订单", "broadcast", "broad",
        "抢单", "去抢", "立即抢", "accept", "grab"
    };

    // =========================================================================
    // install()
    // =========================================================================
    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        final ClassLoader cl = lpparam.classLoader;

        Log.i(TAG, "Installing order grab hooks...");

        // --- Strategy A: Hook GrabOrderButton 点击逻辑 ---
        hookGrabOrderButton(cl);

        // --- Strategy B: Hook AssistantActionExecutor.excActionWithGrabOrder ---
        hookAssistantAction(cl);

        // --- Strategy C: Hook BaseBroadOrder 数据模型 ---
        hookBroadOrderData(cl);

        // --- Strategy D: Hook Push消息 ---
        hookPushCallback(cl);

        // --- Strategy E: Hook UI层订单卡片 ---
        hookOrderCardUI(cl);

        Log.i(TAG, "Order grab hooks installed. Min price: ¥" + MIN_PRICE);
    }

    // =========================================================================
    // Strategy A: GrabOrderButton
    // =========================================================================
    private static void hookGrabOrderButton(ClassLoader cl) {
        try {
            // 新版抢单按钮
            Class<?> grabBtnNew = XposedHelpers.findClass(
                "com.sdu.didi.gsui.broadorder.ordercard.view.GrabOrderButtonNew", cl);

            // Hook所有点击相关方法
            for (Method m : grabBtnNew.getDeclaredMethods()) {
                final String mName = m.getName();
                if (mName.contains("click") || mName.contains("Click") ||
                    mName.contains("perform") || mName.contains("onTap") ||
                    mName.contains("grab") || mName.equals("a") ||
                    mName.equals("b") || mName.equals("c")) {

                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Log.i(TAG, "[GrabButtonNew." + mName + "] Triggered!");
                            recordGrab();
                        }
                    });
                }
            }
            Log.i(TAG, "GrabOrderButtonNew hooked");
        } catch (Throwable t) {
            Log.w(TAG, "GrabOrderButtonNew not found", t);
        }

        try {
            Class<?> grabBtn = XposedHelpers.findClass(
                "com.sdu.didi.gsui.broadorder.ordercard.view.GrabOrderButton", cl);
            for (Method m : grabBtn.getDeclaredMethods()) {
                final String mName = m.getName();
                if (mName.contains("click") || mName.contains("Click") ||
                    mName.contains("perform") || mName.contains("grab")) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Log.i(TAG, "[GrabButton." + mName + "] Triggered!");
                            recordGrab();
                        }
                    });
                }
            }
            Log.i(TAG, "GrabOrderButton hooked");
        } catch (Throwable t) {
            Log.w(TAG, "GrabOrderButton not found", t);
        }
    }

    // =========================================================================
    // Strategy B: AssistantActionExecutor.excActionWithGrabOrder
    // =========================================================================
    private static void hookAssistantAction(ClassLoader cl) {
        try {
            Class<?> executor = XposedHelpers.findClass(
                "com.didi.assistant.main.action.AssistantActionExecutor", cl);

            XposedHelpers.findAndHookMethod(executor, "excActionWithGrabOrder",
                // 参数类型不确定，用可变参数hook
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Log.i(TAG, "[Assistant] excActionWithGrabOrder called!");
                        // 记录参数（订单数据）
                        if (param.args.length > 0) {
                            Object orderData = param.args[0];
                            Log.d(TAG, "[Assistant] Order data: " + orderData);
                        }
                        recordGrab();
                    }
                });

            Log.i(TAG, "AssistantActionExecutor hooked");
        } catch (Throwable t) {
            Log.w(TAG, "AssistantActionExecutor not found", t);
        }
    }

    // =========================================================================
    // Strategy C: BaseBroadOrder — 核心：检测新预约单并自动抢
    // =========================================================================
    private static void hookBroadOrderData(ClassLoader cl) {
        try {
            Class<?> baseBroadOrder = XposedHelpers.findClass(
                "com.didichuxing.driver.broadorder.engine.model.BaseBroadOrder", cl);

            // Hook构造函数 — 新订单创建
            XposedBridge.hookAllConstructors(baseBroadOrder, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Log.i(TAG, "[BroadOrder] NEW ORDER CREATED!");
                    Object order = param.thisObject;

                    // 提取金额
                    float price = extractPrice(order);
                    Log.i(TAG, "[BroadOrder] Price: ¥" + price);

                    // 保存订单引用
                    lastOrderData = new WeakReference<>(order);
                    lastGrabPrice = price;

                    // 判断是否要抢
                    if (shouldGrab(price)) {
                        Log.i(TAG, "[BroadOrder] ★ PRICE OK! Scheduling auto-grab...");
                        scheduleAutoGrab(order, price);
                    } else {
                        Log.d(TAG, "[BroadOrder] Price below threshold or cooling down, skip");
                    }
                }
            });

            // Hook onOrderUpdate / onNewOrder 之类的方法
            for (Method m : baseBroadOrder.getDeclaredMethods()) {
                final String mName = m.getName().toLowerCase();
                if (mName.contains("update") || mName.contains("notify") ||
                    mName.contains("refresh") || mName.contains("onnew") ||
                    mName.contains("show")) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Log.d(TAG, "[BroadOrder." + m.getName() + "] Order updated");
                            // 如果之前没抢到，再次尝试
                            if (lastOrderData != null && lastOrderData.get() != null) {
                                if (shouldGrab(lastGrabPrice)) {
                                    scheduleAutoGrab(lastOrderData.get(), lastGrabPrice);
                                }
                            }
                        }
                    });
                }
            }

            Log.i(TAG, "BaseBroadOrder hooked");
        } catch (Throwable t) {
            Log.w(TAG, "BaseBroadOrder not found", t);
        }

        // 同时hook BroadOrder
        try {
            Class<?> broadOrder = XposedHelpers.findClass(
                "com.didichuxing.driver.broadorder.model.BroadOrder", cl);

            XposedBridge.hookAllConstructors(broadOrder, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Log.i(TAG, "[BroadOrder] NEW ORDER (BroadOrder model)");
                    Object order = param.thisObject;
                    float price = extractPrice(order);
                    lastOrderData = new WeakReference<>(order);
                    lastGrabPrice = price;
                    if (shouldGrab(price)) {
                        scheduleAutoGrab(order, price);
                    }
                }
            });
            Log.i(TAG, "BroadOrder hooked");
        } catch (Throwable t) {
            Log.w(TAG, "BroadOrder not found", t);
        }
    }

    // =========================================================================
    // Strategy D: Push 消息
    // =========================================================================
    private static void hookPushCallback(ClassLoader cl) {
        // Hook PushCallback — 检测新订单推送
        try {
            Class<?> pushCallbackIf = XposedHelpers.findClass(
                "com.didi.sdk.push.IPushCallback", cl);

            // 找所有实现类并hook
            Log.d(TAG, "IPushCallback found, hooking implementations...");
        } catch (Throwable t) {
            Log.w(TAG, "IPushCallback not found", t);
        }

        try {
            Class<?> pushCallback = XposedHelpers.findClass(
                "com.didi.sdk.push.PushCallback", cl);

            for (Method m : pushCallback.getDeclaredMethods()) {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String methodName = m.getName();
                        Log.d(TAG, "[Push] Callback: " + methodName);
                        // 检查是否有订单相关数据
                        for (Object arg : param.args) {
                            if (arg != null) {
                                String argStr = arg.toString();
                                if (argStr.contains("order") || argStr.contains("Order") ||
                                    argStr.contains("price") || argStr.contains("amount") ||
                                    argStr.contains("grab") || argStr.contains("broad")) {
                                    Log.i(TAG, "[Push] Order-related data: " + argStr);
                                }
                            }
                        }
                    }
                });
            }
            Log.i(TAG, "PushCallback hooked");
        } catch (Throwable t) {
            Log.w(TAG, "PushCallback hook fail", t);
        }
    }

    // =========================================================================
    // Strategy E: OrderCard UI — 兜底方案
    // =========================================================================
    private static void hookOrderCardUI(ClassLoader cl) {
        // 如果前面的数据层hook没抓到，UI层兜底
        // Hook OrderCard 的显示方法
        try {
            String[] cardClasses = {
                "com.sdu.didi.gsui.broadorder.ordercard.view.OrderCardView",
                "com.sdu.didi.gsui.orderflow.common.component.broadinfocard.view.BroadInfoCardView",
            };
            for (String className : cardClasses) {
                try {
                    Class<?> cardClass = XposedHelpers.findClass(className, cl);
                    for (Method m : cardClass.getDeclaredMethods()) {
                        String mName = m.getName().toLowerCase();
                        if (mName.contains("show") || mName.contains("bind") ||
                            mName.contains("setdata") || mName.contains("setorder") ||
                            mName.contains("update")) {
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) {
                                    Log.d(TAG, "[UI] " + className + "." + m.getName() + " called");
                                    // 从参数中找订单数据
                                    for (Object arg : param.args) {
                                        if (arg != null) {
                                            float price = extractPrice(arg);
                                            if (price > 0) {
                                                Log.i(TAG, "[UI] Order card shown: ¥" + price);
                                                lastGrabPrice = price;
                                                lastOrderData = new WeakReference<>(arg);
                                                if (shouldGrab(price)) {
                                                    scheduleAutoGrab(arg, price);
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                    Log.i(TAG, className + " hooked");
                } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {
            Log.w(TAG, "OrderCardUI hook fail", t);
        }
    }

    // =========================================================================
    // 核心逻辑：是否应该抢单
    // =========================================================================
    private static boolean shouldGrab(float price) {
        if (!GRAB_ENABLED) {
            Log.d(TAG, "[shouldGrab] Grab disabled");
            return false;
        }

        // 检查金额阈值
        if (MIN_PRICE > 0 && price < MIN_PRICE) {
            Log.d(TAG, "[shouldGrab] Price ¥" + price + " < threshold ¥" + MIN_PRICE);
            return false;
        }

        // 检查冷却
        long now = System.currentTimeMillis();
        if (now < restUntil) {
            long remaining = (restUntil - now) / 1000;
            Log.d(TAG, "[shouldGrab] Resting, " + remaining + "s remaining");
            return false;
        }

        // 检查连续上限
        if (consecutiveGrabs >= MAX_CONSECUTIVE) {
            int restSec = REST_MIN_SEC + RNG.nextInt(REST_MAX_SEC - REST_MIN_SEC + 1);
            restUntil = now + restSec * 1000L;
            Log.i(TAG, "[shouldGrab] Max consecutive reached (" + MAX_CONSECUTIVE +
                  "), resting for " + restSec + "s");
            return false;
        }

        return true;
    }

    // =========================================================================
    // 人手模拟 + 执行抢单
    // =========================================================================
    private static void scheduleAutoGrab(Object orderData, float price) {
        // 计算人手级延迟
        long delayMs = calculateHumanDelay();

        Log.i(TAG, "[AutoGrab] Scheduling grab in " + delayMs + "ms for ¥" + price);

        MAIN_HANDLER.postDelayed(() -> {
            try {
                performGrab(orderData, price);
            } catch (Throwable t) {
                Log.e(TAG, "[AutoGrab] Error during grab", t);
            }
        }, delayMs);
    }

    private static long calculateHumanDelay() {
        // 基础反应时间: 80-200ms
        long base = 80 + RNG.nextInt(121);

        // 15%概率"犹豫"：延迟加倍
        if (RNG.nextFloat() < 0.15f) {
            base *= 2;
            Log.d(TAG, "[HumanSim] Hesitating, delay doubled");
        }

        // 偶尔多思考一下: 10%概率加200-400ms
        if (RNG.nextFloat() < 0.10f) {
            base += 200 + RNG.nextInt(201);
        }

        return base;
    }

    private static void performGrab(Object orderData, float price) {
        Log.i(TAG, "========================================");
        Log.i(TAG, "[★ GRAB ★] Executing grab for ¥" + price);
        Log.i(TAG, "========================================");

        // 尝试多种抢单方式

        // 方式1: 调用 AssistantActionExecutor.excActionWithGrabOrder
        boolean grabbed = false;
        try {
            Class<?> executor = XposedHelpers.findClass(
                "com.didi.assistant.main.action.AssistantActionExecutor",
                orderData.getClass().getClassLoader());
            // 调用静态方法或实例方法
            XposedHelpers.callStaticMethod(executor, "excActionWithGrabOrder", orderData);
            grabbed = true;
            Log.i(TAG, "[Grab] Method 1 (Assistant) succeeded");
        } catch (Throwable t) {
            Log.w(TAG, "[Grab] Method 1 failed: " + t.getMessage());
        }

        // 方式2: 直接触发GrabOrderButton点击
        if (!grabbed) {
            try {
                // 模拟View.performClick
                // 这需要从Activity中找到GrabOrderButton实例
                Log.d(TAG, "[Grab] Method 2 (Button click) - searching for button...");
                // 通过反射遍历当前Activity的View树
                triggerGrabButton();
            } catch (Throwable t) {
                Log.w(TAG, "[Grab] Method 2 failed: " + t.getMessage());
            }
        }

        // 更新状态
        recordGrab();
    }

    private static void triggerGrabButton() {
        // 通过Activity栈找到当前页面的GrabOrderButton
        try {
            // 获取当前Activity
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Object activityThread = XposedHelpers.callStaticMethod(activityThreadClass,
                "currentActivityThread");
            Object activities = XposedHelpers.callMethod(activityThread, "getActivities");
            // ... 遍历找GrabOrderButton实例

            // 简化方案: 直接通过反射触发GrabOrderButton的onClick
            Log.d(TAG, "[triggerGrabButton] Attempting to trigger button");
            // 在LSPosed环境下，可以直接调用View的performClick
            // 这里留作扩展点

        } catch (Throwable t) {
            Log.w(TAG, "[triggerGrabButton] Error", t);
        }
    }

    // =========================================================================
    // 记录抢单
    // =========================================================================
    private static void recordGrab() {
        long now = System.currentTimeMillis();
        lastGrabTime = now;
        totalGrabs++;
        consecutiveGrabs++;

        // 抢单间隔随机冷却
        int cooldownSec = 2 + RNG.nextInt(7); // 2-8秒
        restUntil = now + cooldownSec * 1000L;

        Log.i(TAG, "[Stats] Total grabs: " + totalGrabs +
              ", Consecutive: " + consecutiveGrabs +
              ", Cooldown: " + cooldownSec + "s");
    }

    // =========================================================================
    // 金额提取
    // =========================================================================
    private static float extractPrice(Object obj) {
        if (obj == null) return 0f;

        // 先尝试反射获取价格字段
        String[] priceFields = {
            "price", "totalPrice", "orderPrice", "amount",
            "totalAmount", "estimatePrice", "estPrice",
            "mPrice", "mTotalPrice", "mAmount",
            "total_fee", "estimate_fee", "fee",
            "driverPrice", "driverAmount",
        };

        for (String field : priceFields) {
            try {
                Object val = XposedHelpers.getObjectField(obj, field);
                if (val != null) {
                    if (val instanceof Number) {
                        float f = ((Number) val).floatValue();
                        // 如果值很大（单位是分），转换成元
                        if (f > 500) f = f / 100f;
                        return f;
                    }
                    // 尝试字符串解析
                    String s = val.toString();
                    float f = parsePriceString(s);
                    if (f > 0) return f;
                }
            } catch (Throwable ignored) {}
        }

        // 尝试通过getter方法
        String[] getterPrefixes = {"get", "is", "has"};
        for (String field : new String[]{"Price", "Amount", "TotalPrice", "EstimateFee"}) {
            for (String prefix : getterPrefixes) {
                try {
                    Method m = obj.getClass().getMethod(prefix + field);
                    Object val = m.invoke(obj);
                    if (val instanceof Number) {
                        float f = ((Number) val).floatValue();
                        if (f > 500) f = f / 100f;
                        return f;
                    }
                } catch (Throwable ignored) {}
            }
        }

        // 最后：toString全文搜索
        try {
            String str = obj.toString();
            return parsePriceString(str);
        } catch (Throwable e) {
            return 0f;
        }
    }

    private static float parsePriceString(String s) {
        if (s == null) return 0f;
        Matcher m = PRICE_PATTERN.matcher(s);
        if (m.find()) {
            try {
                return Float.parseFloat(m.group(1));
            } catch (NumberFormatException e) {
                return 0f;
            }
        }
        return 0f;
    }

    // =========================================================================
    // 公开API — 供外部调用配置
    // =========================================================================
    public static void setMinPrice(float price) { MIN_PRICE = price; }
    public static void setEnabled(boolean enabled) { GRAB_ENABLED = enabled; }
    public static void setMaxConsecutive(int max) { MAX_CONSECUTIVE = max; }
    public static long getTotalGrabs() { return totalGrabs; }
    public static long getConsecutiveGrabs() { return consecutiveGrabs; }
    public static void resetConsecutive() { consecutiveGrabs = 0; restUntil = 0; }
}
