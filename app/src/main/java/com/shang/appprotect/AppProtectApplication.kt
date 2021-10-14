package com.shang.appprotect

import android.app.Application

class AppProtectApplication : Application() {

//    類似Java的靜態載入
//    init {
//        System.loadLibrary("native-lib")
//    }

    override fun onCreate() {
        super.onCreate()
        //如果需要在Jni_OnLoad用到Application的context,則需要在onCreate之後去loadLibrary
        System.loadLibrary("native-lib")
    }
}