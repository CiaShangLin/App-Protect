package com.shang.appprotect;

import android.content.Context;

class AppProtect {
    public static native String helloJni();

    public static native boolean shaKeyCompare(Context context);

    public static native boolean libSoCountCheck(Context context);

    public static native boolean assetsCheck(Context context);

    public static native boolean findAppHookName(Context context);
}
