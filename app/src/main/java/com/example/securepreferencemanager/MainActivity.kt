package com.example.securepreferencemanager

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val securePreferenceManager = SecurePreferenceManager(this,"abc","xyz",16)
        securePreferenceManager.putString("key","value")
    }
}