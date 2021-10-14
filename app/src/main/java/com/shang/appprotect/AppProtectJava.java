package com.shang.appprotect;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

class AppProtectJava implements IAppProtect {
    private static final String TAG = "DEBUG_JAVA";

    @Override
    public boolean shaKeyCompare(@NotNull Context context) {
        String myKey = "a3:58:4a:3a:4f:16:ff:d4:81:1a:cf:62:58:be:0e:a6:dd:8c:31:c3";
        try {
            String packageName = context.getPackageName();
            Signature[] signatures = context.getPackageManager()
                    .getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                    .signatures;

            for (Signature signature : signatures) {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                md.update(signature.toByteArray());
                byte[] digest = md.digest();

                StringBuilder stringBuilder = new StringBuilder();

                for (int i = 0; i < digest.length; i++) {
                    if (i != 0) {
                        stringBuilder.append(":");
                    }
                    String hex = Integer.toHexString(digest[i] & 0xff);
                    if (hex.length() == 1) {
                        stringBuilder.append("0");
                    }
                    stringBuilder.append(hex);
                }
                Log.d(TAG, "sha1 key : " + stringBuilder.toString());
                if (!myKey.equals(stringBuilder.toString())) {
                    return false;
                }
            }

        } catch (Exception exception) {
            exception.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean libSoCountCheck(Context context) {
        ArrayList originSo = new ArrayList();
        originSo.add("libnative-lib.so");
        String nativeLibraryDir = context.getApplicationInfo().nativeLibraryDir;
        File libDir = new File(nativeLibraryDir);
        for (File file : libDir.listFiles()) {
            if (!originSo.contains(file.getName())) {
                Log.d(TAG, "lib找到奇怪的so檔");
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean assetsCheck(Context context) {
        try {
            for (String fileName : context.getAssets().list("")) {
                if (fileName.endsWith("so")) {
                    Log.d(TAG, "assets找到奇怪的so檔");
                    return false;
                }
                if (fileName.equals("couldinject")) {
                    Log.d(TAG, "assets找到couldinject");
                    return false;
                }
                if (fileName.endsWith("apk")) {
                    Log.d(TAG, "assets找到奇怪的apk檔");
                    return false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean findAppHookName(Context context) {
        List<ApplicationInfo> applicationInfos = context.getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA);
        for (ApplicationInfo applicationInfo : applicationInfos) {
            if (applicationInfo.packageName.equals("de.robv.android.xposed.installer")) {
                Log.d(TAG, "findAppHookName 找到xposed");
                return false;
            }
            if (applicationInfo.processName.equals("com.saurik.substrate")) {
                Log.d(TAG, "findAppHookName 找到Cydia");
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean isVA() {
        return false;
    }


    @Override
    public boolean applicationNameCheck() {
        return false;
    }


    @NotNull
    @Override
    public String dexSize() {
        return null;
    }
}
