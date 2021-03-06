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
import java.util.Arrays;
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
                Log.d(TAG, "lib???????????????so???");
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
                    Log.d(TAG, "assets???????????????so???");
                    return false;
                }
                if (fileName.equals("couldinject")) {
                    Log.d(TAG, "assets??????couldinject");
                    return false;
                }
                if (fileName.endsWith("apk")) {
                    Log.d(TAG, "assets???????????????apk???");
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
                Log.d(TAG, "findAppHookName ??????xposed");
                return false;
            }
            if (applicationInfo.processName.equals("com.saurik.substrate")) {
                Log.d(TAG, "findAppHookName ??????Cydia");
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean applicationNameCheck(Context context) {
        try {
            String packageName = context.getPackageName();
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(packageName, 0);
            return info.className.equals("com.shang.appprotect.AppProtectApplication");
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean isVA(Context context) {
        ArrayList<String> virtualPkgs = new ArrayList<String>();
        virtualPkgs.add("com.bly.dkplat");
        virtualPkgs.add("dkplugin.pke.nnp");
        virtualPkgs.add("com.by.chaos");
        virtualPkgs.add("com.excelliance.dualaid");
        virtualPkgs.add("com.excelliance.dualaid.b64");
        virtualPkgs.add("com.lody.virtual");
        virtualPkgs.add("com.qihoo.magic");
        virtualPkgs.add("multi.parallel.dualspace.cloner");
        virtualPkgs.add("com.polar.apps.dual.multi.accounts");
        virtualPkgs.add("com.lbe.parallel.intl");
        virtualPkgs.add("com.lbe.parallel.intl.arm64");
        virtualPkgs.add("com.applisto.appcloner");
        virtualPkgs.add("com.applisto.appcloner");
        virtualPkgs.add("com.cloneapp.parallelspace.dualspace");

        String path = context.getFilesDir().getPath();
        for (String pkgs : virtualPkgs) {
            if (path.contains(pkgs)) {
                Log.d(TAG, "isVA find " + pkgs);
                return true;
            }
        }
        return false;
    }
}
