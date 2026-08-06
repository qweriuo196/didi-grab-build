#!/bin/bash
# ============================================================
# DiDi Grab Xposed Module Build Script
# 用法:
#   ./build.sh              # 编译release APK
#   ./build.sh debug        # 编译debug APK
#   ./build.sh install      # 编译并安装到设备
#
# 前置条件:
#   - Android SDK (设置 ANDROID_HOME 或 ANDROID_SDK_ROOT)
#   - JDK 11+
#   - Gradle wrapper (首次运行自动下载)
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "  DiDi Grab Xposed Module Builder"
echo "  Target: com.sdu.didi.gsui"
echo "========================================"

# Check Java
JAVA_VER=$(java -version 2>&1 | head -1 | grep -oP '\d+' | head -1)
if [ -z "$JAVA_VER" ] || [ "$JAVA_VER" -lt 11 ]; then
    echo "ERROR: JDK 11+ required. Found: java $JAVA_VER"
    exit 1
fi
echo "[OK] Java version: $JAVA_VER"

# Check Android SDK
if [ -z "$ANDROID_HOME" ]; then
    ANDROID_HOME="$ANDROID_SDK_ROOT"
fi
if [ -z "$ANDROID_HOME" ]; then
    # Common paths
    for p in "$HOME/Android/Sdk" "$HOME/android-sdk" "/opt/android-sdk" "$HOME/Library/Android/sdk"; do
        if [ -d "$p" ]; then
            ANDROID_HOME="$p"
            break
        fi
    done
fi
if [ -z "$ANDROID_HOME" ] || [ ! -d "$ANDROID_HOME" ]; then
    echo "WARN: ANDROID_HOME not set. Create local.properties..."
    echo "sdk.dir=$HOME/Android/Sdk" > local.properties
else
    echo "[OK] ANDROID_HOME: $ANDROID_HOME"
    echo "sdk.dir=$ANDROID_HOME" > local.properties
fi

# Generate gradle wrapper if not exists
if [ ! -f "gradlew" ]; then
    echo "[...] Generating Gradle wrapper..."
    if command -v gradle &>/dev/null; then
        gradle wrapper --gradle-version 8.5
    else
        echo "ERROR: gradle not found. Please install Gradle or run 'gradle wrapper' first."
        exit 1
    fi
fi

# Build
MODE="${1:-release}"
if [ "$MODE" = "release" ]; then
    TASK="assembleRelease"
    APK_PATH="app/build/outputs/apk/release/app-release-unsigned.apk"
elif [ "$MODE" = "debug" ]; then
    TASK="assembleDebug"
    APK_PATH="app/build/outputs/apk/debug/app-debug.apk"
else
    TASK="$MODE"
    APK_PATH=""
fi

echo ""
echo "[...] Building: ./gradlew $TASK"
./gradlew $TASK

# Find APK
if [ -z "$APK_PATH" ]; then
    APK_PATH=$(find app/build -name "*.apk" -type f | head -1)
fi

if [ -f "$APK_PATH" ]; then
    SIZE=$(du -h "$APK_PATH" | cut -f1)
    echo ""
    echo "========================================"
    echo "  BUILD SUCCESS"
    echo "  APK: $APK_PATH"
    echo "  Size: $SIZE"
    echo "========================================"

    # Install if requested
    if [ "$MODE" = "install" ] || [ "$2" = "install" ]; then
        echo ""
        echo "[...] Installing to device..."
        adb install -r "$APK_PATH"
        echo "[OK] Installed. Now:"
        echo "  1. Open LSPosed Manager"
        echo "  2. Enable 'DiDi Grab' module"
        echo "  3. Check 'com.sdu.didi.gsui' in scope"
        echo "  4. Force-stop DiDi Driver app"
        echo "  5. Reopen DiDi Driver"
    fi
else
    echo "ERROR: APK not found. Check build output above."
    exit 1
fi
