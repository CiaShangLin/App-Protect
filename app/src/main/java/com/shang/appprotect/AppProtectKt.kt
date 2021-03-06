package com.shang.appprotect

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PackageManager.GET_RESOLVED_FILTER
import android.util.Log
import java.io.File
import java.lang.StringBuilder
import java.security.MessageDigest
import kotlin.experimental.and

class AppProtectKt : IAppProtect {
    companion object {
        private const val TAG = "DEBUG_KT"
    }

    override fun shaKeyCompare(context: Context): Boolean {
        //這是我debug的SHA1 key
        val myKey = "a3:58:4a:3a:4f:16:ff:d4:81:1a:cf:62:58:be:0e:a6:dd:8c:31:c3"
        try {
            val packageName = context.packageName
            val signatures = context.packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNATURES
            ).signatures
            signatures?.forEach {
                val md = MessageDigest.getInstance("SHA1")
                md.update(it.toByteArray())
                val digest = md.digest()
                val stringBuilder = StringBuilder()
                digest.forEachIndexed { index, byte ->
                    if (index != 0) {
                        stringBuilder.append(":")
                    }

                    //0xff=255 但是kotlin的byte範圍-128~127 所以只好轉成int
                    val hex = Integer.toHexString((byte.toInt() and 0xff))
                    if (hex.length == 1) {
                        stringBuilder.append("0")
                    }
                    stringBuilder.append(hex)
                }
                Log.d(TAG, "sha1 key : ${stringBuilder.toString()}")
                if (myKey != stringBuilder.toString()) {
                    return false
                }
            }

        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
        return true
    }

    override fun libSoCountCheck(context: Context): Boolean {
        val originSo = listOf<String>("libnative-lib.so")
        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir
        val libDir = File(nativeLibraryDir)
        libDir.listFiles().forEach {
            //如果有找到不同的so就代表被新增其他的so檔
            if (!originSo.contains(it.name)) {
                Log.d(TAG, "lib找到奇怪的so檔")
                return false
            }
        }
        return true
    }

    //預設會有images和webkit東東
    override fun assetsCheck(context: Context): Boolean {
        context.assets.list("")?.forEach {
            if (it.endsWith("so")) {
                Log.d(TAG, "assets找到奇怪的so檔")
                return false
            }
            if (it == "couldinject") {
                Log.d(TAG, "assets找到couldinject")
                return false
            }
            if (it.endsWith("apk")) {
                Log.d(TAG, "assets找到奇怪的apk檔")
                return false
            }
        }
        return true
    }

    override fun findAppHookName(context: Context): Boolean {
        val applicationInfo =
            context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        applicationInfo.forEach {
            if (it.packageName == "de.robv.android.xposed.installer") {
                Log.d(TAG, "findAppHookName 找到xposed")
                return false
            }
            if (it.processName == "com.saurik.substrate") {
                Log.d(TAG, "findAppHookName 找到Cydia")
                return false
            }
        }
        return true
    }

    override fun applicationNameCheck(context: Context): Boolean {
        val packageName = context.packageName
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        return info.className == "com.shang.appprotect.AppProtectApplication"
    }

    override fun isVA(context: Context): Boolean {
        val virtualPkgs = arrayOf(
            "com.bly.dkplat",                        //多开分身
            "dkplugin.pke.nnp",                      //當初複製來的就有了,但app可能消失了吧
            "com.by.chaos",                          //當初複製來的就有了,但app可能消失了吧
            "com.lbe.parallel",                      //LBE平行空間
            "com.excelliance.dualaid",               //双开助手
            "com.excelliance.dualaid.b64",           //双开助手 64bit
            "com.lody.virtual",                      //VirtualApp這個應該是libary
            "com.qihoo.magic",                       //分身大师
            "multi.parallel.dualspace.cloner",       //多開空間
            "com.polar.apps.dual.multi.accounts",    //Multi Accounts
            "com.lbe.parallel.intl",                 //Parallel Space
            "com.lbe.parallel.intl.arm64",           //Parallel Space - 64Bit Support
            "com.applisto.appcloner",                //App Cloner
            "com.cloneapp.parallelspace.dualspace",  //Clone App
        )
        virtualPkgs.forEach {
            if (context.filesDir.path.contains(it)) {
                Log.d(TAG,"isVA find $it")
                return true
            }
        }
        return false
    }
}