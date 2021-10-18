package com.shang.appprotect

import android.content.Context

interface IAppProtect {
    fun shaKeyCompare(context:Context): Boolean
    fun libSoCountCheck(context:Context): Boolean
    fun assetsCheck(context:Context): Boolean
    fun findAppHookName(context:Context): Boolean
    fun applicationNameCheck(context: Context): Boolean
    fun isVA(context: Context): Boolean
}