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
import java.text.SimpleDateFormat
import java.util.*
import kotlin.collections.ArrayList

class BlockDataToFromFile : AppCompatActivity(), VosWrapper.Callback , VGExceptionHandler {

    private lateinit var mVos: Vos
    private lateinit var mStartVosThread: Thread
    var vGuardManager: VGuard? = null

    // LifecycleHook to notify VGuard of activity's lifecycle
    private lateinit var hook: VGuardLifecycleHook

    // For VGuard to notify host app of events
    private lateinit var broadcastRcvr: VGuardBroadcastReceiver


    private lateinit var et_input_encrypt: EditText
    private lateinit var et_input_encrypt_password: EditText
    private lateinit var et_input_decrypt: EditText
    private lateinit var et_input_oldpass: EditText
    private lateinit var et_input_update_newpass: EditText
    private lateinit var et_input_confrim_newpass: EditText

    private lateinit var bt_save_encrypt: Button
    private lateinit var bt_save_decrypt: Button
    private lateinit var bt_update_pass: Button

    private lateinit var tv_decrypt: TextView

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


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_block_data_to_from_file)

        mVos = Vos(this)
        mVos.registerVosWrapperCallback(this)
        startVos(this)
        setupVGuard(this)


        et_input_encrypt = findViewById(R.id.et_encrypt_bdata)
        et_input_encrypt_password = findViewById(R.id.et_password_input_bdata)
        et_input_decrypt = findViewById(R.id.et_decrypt_password_bdata)
        et_input_oldpass = findViewById(R.id.et_oldpass_bdata)
        et_input_update_newpass = findViewById(R.id.et_passwordnewt_bdata)
        et_input_confrim_newpass = findViewById(R.id.et_password_confirm_bdata)

        bt_save_encrypt = findViewById(R.id.bt_save_bdata)
        bt_save_decrypt = findViewById(R.id.bt_read_decrypt_bdata)
        bt_update_pass = findViewById(R.id.bt_updatepass_bdata)

        tv_decrypt = findViewById(R.id.tv_bdatadecrypt_bdata)

        bt_save_decrypt.visibility = View.GONE

        bt_save_encrypt.setOnClickListener {
            enc()
            bt_save_decrypt.visibility = View.VISIBLE
        }
        bt_save_decrypt.setOnClickListener {
            dec()
        }
        bt_update_pass.setOnClickListener {
            updatePass()
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
                        BlockDataToFromFile.TAG,
                        "ProcessorVers: $version || TroubleShootingID: $troubleShootingID"
                    )
                } else {
                    // Failed to start V-OS
                    Log.e(BlockDataToFromFile.TAG, "Failed to start V-OS")
                }
            } catch (e: VGException) {
                Log.e(BlockDataToFromFile.TAG, e.message.toString())
                e.printStackTrace()
            }
        }

        mStartVosThread.start()
    }


    private fun enc(){
        val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"
        val data = et_input_encrypt.text.toString().toByteArray()
        val password = et_input_encrypt_password.text.toString() + "P@ssw0rd"

        SecureFileIO.encryptData(
            data, encryptedFilePath,
            password, false)

    }

    private fun dec(){
        val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"
        val password = et_input_decrypt.text.toString() + "P@ssw0rd"
        try {
            val decString = SecureFileIO.decryptFile(encryptedFilePath , password)
            tv_decrypt.text = "Decrypterd File : " + String(decString)
        }catch (e: IOException){
            Toast.makeText(this , "Make sure the password is correct !" , Toast.LENGTH_SHORT).show()
        }

    }

    private fun updatePass(){
        val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"
        val oldPass = et_input_oldpass.text.toString() + "P@ssw0rd"
        val newPass = et_input_update_newpass.toString() + "P@ssw0rd"
        val newPassConfirm = et_input_confrim_newpass.toString() + "P@ssw0rd"

        if (oldPass.isEmpty() || newPass.isEmpty() || newPassConfirm.isEmpty()){
            Toast.makeText(this , "All Field must ne filled !" , Toast.LENGTH_SHORT).show()
        }else{
            try {
                SecureFileIO.updateFile(encryptedFilePath , newPass , oldPass)
                Toast.makeText(this , "Password Updated" , Toast.LENGTH_SHORT).show()
            }catch (e: IOException){
                Log.d("passeror", "updatePass: ")
            }
        }
    }



    public fun setupVGuard(activity: Activity){
        receiveVGuardBroadcast(activity)
        registerLocalBroadcast()
        setupAppProtection()
    }

    private fun receiveVGuardBroadcast(activity: Activity){
        broadcastRcvr = object : VGuardBroadcastReceiver(activity) {
            override fun onReceive(context: Context?, intent: Intent?) {
                super.onReceive(context, intent)

                when {
                    BlockDataToFromFile.PROFILE_LOADED == intent?.action -> Log.d(
                        BlockDataToFromFile.TAG_ON_RECEIVE,
                        "PROFILE_LOADED"
                    )

                    ACTION_SCAN_COMPLETE == intent?.action ->
                        onScanComplete(intent)


                    VGUARD_OVERLAY_DETECTED_DISABLE == intent?.action -> Log.d(
                        BlockDataToFromFile.TAG_ON_RECEIVE,
                        "VGUARD_OVERLAY_DETECTED_DISABLE"
                    )

                    VGUARD_OVERLAY_DETECTED == intent?.action -> Log.d(
                        BlockDataToFromFile.TAG_ON_RECEIVE,
                        "VGUARD_OVERLAY_DETECTED"
                    )

                    VGUARD_STATUS == intent?.action -> {
                        Log.d(
                            BlockDataToFromFile.TAG_VGUARD_STATUS,
                            "HasExtraVGuardInitStatus: ${intent.hasExtra(VGUARD_INIT_STATUS)}"
                        )

                        if (intent.hasExtra(VGUARD_MESSAGE)) {
                            val message = intent.getStringExtra(VGUARD_MESSAGE)
                            var allMessage = "\n $VGUARD_MESSAGE : $message"
                            if (message != null) {
                                Log.d("MSG", message)
                            }
                            Log.d(BlockDataToFromFile.TAG_VGUARD_MESSAGE, allMessage)
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

                                Log.d(BlockDataToFromFile.TAG_HANDLE_THREAT_POLICY, builder.toString())
                            }
                        }

                        if (intent.hasExtra(VGUARD_INIT_STATUS)) {
                            Log.d(
                                BlockDataToFromFile.TAG_VGUARD_STATUS,
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
                                        BlockDataToFromFile.TAG_VGUARD_STATUS,
                                        "code: ${jsonObject.getString("code")}"
                                    )
                                    Log.d(
                                        BlockDataToFromFile.TAG_VGUARD_STATUS,
                                        "code: ${jsonObject.getString("description")}"
                                    )
                                    message += jsonObject.toString()
                                } catch (e: java.lang.Exception) {
                                    Log.e(BlockDataToFromFile.TAG_VGUARD_STATUS, e.message.toString())
                                    e.printStackTrace()
                                }
                                Log.d(BlockDataToFromFile.TAG_VGUARD_STATUS, message)
                            }
                        }

                        if (intent.hasExtra(VGUARD_SSL_ERROR_DETECTED)) {
                            Log.d(
                                BlockDataToFromFile.TAG_VGUARD_STATUS,
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
                                        BlockDataToFromFile.TAG_VGUARD_STATUS,
                                        jsonObject.getString(VGUARD_ALERT_TITLE)
                                    )
                                    Log.d(
                                        BlockDataToFromFile.TAG_VGUARD_STATUS,
                                        jsonObject.getString(VGUARD_ALERT_MESSAGE)
                                    )
                                    message += jsonObject.toString()
                                } catch (e: java.lang.Exception) {
                                    Log.e(BlockDataToFromFile.TAG_VGUARD_STATUS, e.message.toString())
                                    e.printStackTrace()
                                }
                            }
                        }
                    }

                    VOS_READY == intent?.action -> {
                        val firmwareReturnCode =
                            intent.getLongExtra(
                                BlockDataToFromFile.VOS_FIRMWARE_RETURN_CODE_KEY,
                                BlockDataToFromFile.DEFAULT_VALUE
                            )
                        if (firmwareReturnCode >= BlockDataToFromFile.DEFAULT_VALUE) {
                            // if the `VGuardManager` is not available,
                            // create a `VGuardManager` instance from `VGuardFactory`
                            if (vGuardManager == null) {
                                vGuardManager = VGuardFactory.getInstance()
                                hook = ActivityLifecycleHook(vGuardManager)

                                val isStarted = vGuardManager?.isVosStarted.toString()
                                val valueTID = vGuardManager?.troubleshootingId.toString()



                                Log.d(BlockDataToFromFile.TAG_VOS_READY, "isVosStarted: $isStarted")
                                Log.d(BlockDataToFromFile.TAG_VOS_READY, "TID: $valueTID")
                            }
                        } else {
                            // Error handling
                            Log.d(BlockDataToFromFile.TAG_VOS_READY, "vos_ready_error_firmware")
                        }
                        Log.d(BlockDataToFromFile.TAG_VOS_READY, "VOS_READY")
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
            BlockDataToFromFile.TAG_ON_RECEIVE,
            "ACTION_SCAN_COMPLETE"
        )
    }




    private fun registerLocalBroadcast(){
        LocalBroadcastManager.getInstance(this).apply {
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.ACTION_FINISH))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.ACTION_SCAN_COMPLETE))
            registerReceiver(broadcastRcvr, IntentFilter(BlockDataToFromFile.PROFILE_LOADED))
            registerReceiver(broadcastRcvr, IntentFilter(VGuardBroadcastReceiver.VOS_READY))
            registerReceiver(broadcastRcvr, IntentFilter(BlockDataToFromFile.PROFILE_THREAT_RESPONSE))
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
            Log.e(BlockDataToFromFile.TAG, e.message.toString())
            e.printStackTrace()
        }
    }

    override fun onNotified(p0: Int, p1: Int): Boolean {
        TODO("Not yet implemented")
    }

    override fun handleException(e: java.lang.Exception?) {
        TODO("Not yet implemented")
    }
}
