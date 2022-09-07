package id.co.sistema.vkey

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Parcelable
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import com.vkey.android.internal.vguard.engine.BasicThreatInfo
import com.vkey.android.vguard.*
import com.vkey.securefileio.SecureFileIO
import org.json.JSONObject
import vkey.android.vos.Vos
import vkey.android.vos.VosWrapper
import java.io.IOException
import java.lang.Exception
import java.text.SimpleDateFormat
import java.util.*
import kotlin.collections.ArrayList

class BlockDataEncryption : AppCompatActivity(), VosWrapper.Callback , VGExceptionHandler {

    private lateinit var mVos: Vos
    private lateinit var mStartVosThread: Thread
    var vGuardManager: VGuard? = null

    // LifecycleHook to notify VGuard of activity's lifecycle
    private lateinit var hook: VGuardLifecycleHook

    // For VGuard to notify host app of events
    private lateinit var broadcastRcvr: VGuardBroadcastReceiver

    private lateinit var et_inputenc: EditText
    private lateinit var et_passenc: EditText
    private lateinit var et_passdec: EditText

    private lateinit var bt_enc: Button
    private lateinit var bt_dec: Button

    private lateinit var tv_dec_result: TextView



    companion object {
        private const val TAG = "StringActivity"
        private const val TAG_SFIO = "SecureFileIO"
        private const val STR_INPUT = "Quick brown fox jumps over the lazy dog. 1234567890 some_one@somewhere.com"
        private const val PASSWORD = "P@ssw0rd"
        private const val PROFILE_LOADED = "vkey.android.vguard.PROFILE_LOADED"
        private const val VOS_FIRMWARE_RETURN_CODE_KEY = "vkey.android.vguard.FIRMWARE_RETURN_CODE"
        private const val PROFILE_THREAT_RESPONSE = "vkey.android.vguard.PROFILE_THREAT_RESPONSE"
        private const val TAG_ON_RECEIVE = "OnReceive"
        private const val TAG_VGUARD_STATUS = "VGuardStatus"
        private const val TAG_VOS_READY = "VosReady"
        private const val TAG_VGUARD_MESSAGE = "VguardMessage"
        private const val TAG_HANDLE_THREAT_POLICY = "HandleThreat"
        private const val DEFAULT_VALUE = 0L
    }

    private lateinit var cipher: ByteArray



    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_block_data_encryption)

        mVos = Vos(this)
        mVos.registerVosWrapperCallback(this)
        startVos(this)
        setupVGuard(this)

        et_inputenc = findViewById(R.id.et_enc_bdata1)


        bt_enc = findViewById(R.id.bt_enc_bdata1)
        bt_dec = findViewById(R.id.bt_dc_bdata1)

        tv_dec_result = findViewById(R.id.tv_dc_bdata1)

        bt_dec.visibility = View.GONE
        bt_enc.setOnClickListener {
            enc()
            bt_dec.visibility = View.VISIBLE
        }

        bt_dec.setOnClickListener {
            dec()
        }

    }


    private fun startVos(ctx: Context) {
        mStartVosThread = Thread {
            try {
                // Get the kernel data in byte from `firmware` asset file
                val inputStream = ctx.assets.open("firmware")
                val kernelData = inputStream.readBytes()
                inputStream.read(kernelData)
                inputStream.close()

                // Start V-OS
                val vosReturnCode = mVos.start(kernelData, null, null, null, null)

                if (vosReturnCode > 0) {
                    // Successfully started V-OS
                    // Instantiate a `VosWrapper` instance for calling V-OS Processor APIs
                    if (vGuardManager == null) {
                        vGuardManager = VGuardFactory.getInstance()}

                    val vosWrapper = VosWrapper.getInstance(ctx)
                    val version = vosWrapper.processorVersion
                    val troubleShootingID = String(vosWrapper.troubleshootingId)

                    Log.d(
                        BlockDataEncryption.TAG,
                        "ProcessorVers: $version || TroubleShootingID: $troubleShootingID"
                    )
                } else {
                    // Failed to start V-OS
                    Log.e(BlockDataEncryption.TAG, "Failed to start V-OS")
                }
            } catch (e: VGException) {
                Log.e(BlockDataEncryption.TAG, e.message.toString())
                e.printStackTrace()
            }
        }

        mStartVosThread.start()
    }


    private fun enc() {
        cipher  = et_inputenc.text.toString().toByteArray()
        SecureFileIO.encryptData(cipher)

    }


    private fun dec(){
        try {
            SecureFileIO.decryptData(cipher)
            tv_dec_result.text = "Decrypterd File : " + String(cipher)
        }catch (e: IOException){
            Toast.makeText(this , "Eror $e" , Toast.LENGTH_SHORT).show()
        }

    }


    private fun setupVGuard(activity: Activity){
        receiveVGuardBroadcast(activity)
        registerLocalBroadcast()
        setupAppProtection()
    }

    private fun receiveVGuardBroadcast(activity: Activity){
        broadcastRcvr = object : VGuardBroadcastReceiver(activity) {
            override fun onReceive(context: Context?, intent: Intent?) {
                super.onReceive(context, intent)

                when {
                    BlockDataEncryption.PROFILE_LOADED == intent?.action -> Log.d(
                        BlockDataEncryption.TAG_ON_RECEIVE,
                        "PROFILE_LOADED"
                    )

                    ACTION_SCAN_COMPLETE == intent?.action ->
                        onScanComplete(intent)


                    VGUARD_OVERLAY_DETECTED_DISABLE == intent?.action -> Log.d(
                        BlockDataEncryption.TAG_ON_RECEIVE,
                        "VGUARD_OVERLAY_DETECTED_DISABLE"
                    )

                    VGUARD_OVERLAY_DETECTED == intent?.action -> Log.d(
                        BlockDataEncryption.TAG_ON_RECEIVE,
                        "VGUARD_OVERLAY_DETECTED"
                    )

                    VGUARD_STATUS == intent?.action -> {
                        Log.d(
                            BlockDataEncryption.TAG_VGUARD_STATUS,
                            "HasExtraVGuardInitStatus: ${intent.hasExtra(VGUARD_INIT_STATUS)}"
                        )

                        if (intent.hasExtra(VGUARD_MESSAGE)) {
                            val message = intent.getStringExtra(VGUARD_MESSAGE)
                            var allMessage = "\n $VGUARD_MESSAGE : $message"
                            if (message != null) {
                                Log.d("MSG", message)
                            }
                            Log.d(BlockDataEncryption.TAG_VGUARD_MESSAGE, allMessage)
                        }

                        if (intent.hasExtra(VGUARD_HANDLE_THREAT_POLICY)) {
                            val detectedThreats =
                                intent.getParcelableArrayListExtra<Parcelable>(SCAN_COMPLETE_RESULT)
                            val builder = StringBuilder()

                            if (detectedThreats != null) {
                                for (info in detectedThreats) {
                                    val infoStr = (info as BasicThreatInfo).toString()
                                    builder.append("$infoStr \n")
                                }

                                val highestResponse =
                                    intent.getIntExtra(VGUARD_HIGHEST_THREAT_POLICY, -1)
                                val alertTitle = intent.getStringExtra(VGUARD_ALERT_TITLE)
                                val alertMessage = intent.getStringExtra(VGUARD_ALERT_MESSAGE)
                                val disabledAppExpired =
                                    intent.getLongExtra(VGUARD_DISABLED_APP_EXPIRED, 0)

                                when {
                                    highestResponse > 0 -> builder.append("highest policy: $highestResponse\n")
                                    !TextUtils.isEmpty(alertTitle) -> builder.append("alertTitle: $alertTitle\n")
                                    !TextUtils.isEmpty(alertMessage) -> builder.append("alertMessage: $alertMessage\n")
                                    disabledAppExpired > 0 -> {
                                        val format = SimpleDateFormat(
                                            "yyyy-MMdd HH:mm:ss",
                                            Locale.getDefault()
                                        )
                                        val activeDate = format.format(Date(disabledAppExpired))
                                        builder.append("App can use again after: $activeDate\n")
                                    }
                                }

                                Log.d(BlockDataEncryption.TAG_HANDLE_THREAT_POLICY, builder.toString())
                            }
                        }

                        if (intent.hasExtra(VGUARD_INIT_STATUS)) {
                            Log.d(
                                BlockDataEncryption.TAG_VGUARD_STATUS,
                                "VGUARD_INIT_STATUS: ${
                                    intent.getBooleanExtra(
                                        VGUARD_INIT_STATUS,
                                        false
                                    )
                                }"
                            )
                            val initStatus = intent.getBooleanExtra(VGUARD_INIT_STATUS, false)
                            var message = "\n $VGUARD_STATUS: $initStatus"

                            if (!initStatus) {
                                try {
                                    val jsonObject =
                                        JSONObject(intent.getStringExtra(VGUARD_MESSAGE))
                                    Log.d(
                                        BlockDataEncryption.TAG_VGUARD_STATUS,
                                        "code: ${jsonObject.getString("code")}"
                                    )
                                    Log.d(
                                        BlockDataEncryption.TAG_VGUARD_STATUS,
                                        "code: ${jsonObject.getString("description")}"
                                    )
                                    message += jsonObject.toString()
                                } catch (e: java.lang.Exception) {
                                    Log.e(BlockDataEncryption.TAG_VGUARD_STATUS, e.message.toString())
                                    e.printStackTrace()
                                }
                                Log.d(BlockDataEncryption.TAG_VGUARD_STATUS, message)
                            }
                        }

                        if (intent.hasExtra(VGUARD_SSL_ERROR_DETECTED)) {
                            Log.d(
                                BlockDataEncryption.TAG_VGUARD_STATUS,
                                "VGUARD_SSL_ERROR_DETECTED: ${
                                    intent.getBooleanExtra(
                                        VGUARD_SSL_ERROR_DETECTED,
                                        false
                                    )
                                }"
                            )
                            val sslError = intent.getBooleanExtra(VGUARD_SSL_ERROR_DETECTED, false)
                            var message = "\n $VGUARD_SSL_ERROR_DETECTED: $sslError"

                            if (sslError) {
                                try {
                                    val jsonObject =
                                        JSONObject(intent.getStringExtra(VGUARD_MESSAGE))
                                    Log.d(
                                        BlockDataEncryption.TAG_VGUARD_STATUS,
                                        jsonObject.getString(VGUARD_ALERT_TITLE)
                                    )
                                    Log.d(
                                        BlockDataEncryption.TAG_VGUARD_STATUS,
                                        jsonObject.getString(VGUARD_ALERT_MESSAGE)
                                    )
                                    message += jsonObject.toString()
                                } catch (e: java.lang.Exception) {
                                    Log.e(BlockDataEncryption.TAG_VGUARD_STATUS, e.message.toString())
                                    e.printStackTrace()
                                }
                            }
                        }
                    }

                    VOS_READY == intent?.action -> {
                        val firmwareReturnCode =
                            intent.getLongExtra(
                                BlockDataEncryption.VOS_FIRMWARE_RETURN_CODE_KEY,
                                BlockDataEncryption.DEFAULT_VALUE
                            )
                        if (firmwareReturnCode >= BlockDataEncryption.DEFAULT_VALUE) {
                            // if the `VGuardManager` is not available,
                            // create a `VGuardManager` instance from `VGuardFactory`
                            if (vGuardManager == null) {
                                vGuardManager = VGuardFactory.getInstance()
                                hook = ActivityLifecycleHook(vGuardManager)

                                val isStarted = vGuardManager?.isVosStarted.toString()
                                val valueTID = vGuardManager?.troubleshootingId.toString()



                                Log.d(BlockDataEncryption.TAG_VOS_READY, "isVosStarted: $isStarted")
                                Log.d(BlockDataEncryption.TAG_VOS_READY, "TID: $valueTID")
                            }
                        } else {
                            // Error handling
                            Log.d(BlockDataEncryption.TAG_VOS_READY, "vos_ready_error_firmware")
                        }
                        Log.d(BlockDataEncryption.TAG_VOS_READY, "VOS_READY")
                    }
                }
            }
        }
    }

    private fun onScanComplete(intent: Intent?){
        val detectThreat = intent?.getParcelableArrayListExtra<Parcelable>(
            VGuardBroadcastReceiver.SCAN_COMPLETE_RESULT
        ) as ArrayList<Parcelable>

        val threat: ArrayList<BasicThreatInfo> = arrayListOf()
        for(item in detectThreat){
            threat.add(item as BasicThreatInfo)
        }

        Handler(Looper.getMainLooper()).postDelayed({
            org.greenrobot.eventbus.EventBus.getDefault().post(threat)
        }, 3000L)
        Log.d(
            BlockDataEncryption.TAG_ON_RECEIVE,
            "ACTION_SCAN_COMPLETE"
        )
    }




    private fun registerLocalBroadcast(){
        LocalBroadcastManager.getInstance(this).apply {
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.ACTION_FINISH))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.ACTION_SCAN_COMPLETE))
            registerReceiver(broadcastRcvr, IntentFilter(BlockDataEncryption.PROFILE_LOADED))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.VOS_READY))
            registerReceiver(broadcastRcvr, IntentFilter(BlockDataEncryption.PROFILE_THREAT_RESPONSE))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.VGUARD_OVERLAY_DETECTED))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.VGUARD_OVERLAY_DETECTED_DISABLE))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.VGUARD_STATUS))
        }
    }

    private fun setupAppProtection(){
        try {
            val config = VGuardFactory.Builder()
                .setDebugable(true)
                .setAllowsArbitraryNetworking(true)
                .setMemoryConfiguration(MemoryConfiguration.DEFAULT)
                .setVGExceptionHandler(this)

            VGuardFactory().getVGuard(this, config)
        } catch (e: java.lang.Exception) {
            Log.e(BlockDataEncryption.TAG, e.message.toString())
            e.printStackTrace()
        }
    }

    override fun onNotified(p0: Int, p1: Int): Boolean {
        TODO("Not yet implemented")
    }

    override fun handleException(e: Exception?) {
        TODO("Not yet implemented")
    }
}