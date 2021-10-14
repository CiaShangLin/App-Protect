package com.shang.appprotect

import android.content.Context

interface IAppProtect {
    fun shaKeyCompare(context:Context): Boolean
    fun libSoCountCheck(context:Context): Boolean
    fun assetsCheck(context:Context): Boolean
    fun findAppHookName(): Boolean
    fun isVA(): Boolean
    fun applicationNameCheck(): Boolean
    fun dexSize(): String
}