package com.shang.appprotect

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import java.lang.StringBuilder

//這裡只有呼叫Jni的方法
class MainActivity : AppCompatActivity() {

    private lateinit var tvKt: TextView

    private val appProtectKt = AppProtectKt()
    private val appProtectJava = AppProtectJava()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val strKt = StringBuilder()

        strKt.append("helloJni : " + AppProtect.helloJni())
            .append("\n")
            .append("shaKeyCompare : ${AppProtect.shaKeyCompare(this)}")
            .append("\n")
            .append("libSoCountCheck : ${AppProtect.libSoCountCheck(this)}")
            .append("\n")
            .append("assetsCheck : ${AppProtect.assetsCheck(this)}")
            .append("\n")
            .append("findAppHookName : ${AppProtect.findAppHookName(this)}")

        tvKt = findViewById(R.id.tvKt)
        tvKt.text = strKt.toString()
    }
}