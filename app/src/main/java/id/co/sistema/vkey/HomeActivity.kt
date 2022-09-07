package id.co.sistema.vkey

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.opengl.Visibility
import android.os.*
import android.util.Log
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.play.core.splitinstall.SplitInstallManager
import com.google.android.play.core.splitinstall.SplitInstallManagerFactory
import com.google.android.play.core.splitinstall.SplitInstallStateUpdatedListener
import com.google.android.play.core.splitinstall.model.SplitInstallSessionStatus
import com.google.common.eventbus.Subscribe
import com.vkey.android.internal.vguard.engine.BasicThreatInfo
import com.vkey.android.vguard.*
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.ThreadMode
import vkey.android.vos.Vos
import vkey.android.vos.VosWrapper

class HomeActivity : AppCompatActivity(), VosWrapper.Callback  {

    var vGuardManager: VGuard? = null
    private val VOS_FIRMWARE_RETURN_CODE_KEY = "vkey.android.vguard.FIRMWARE_RETURN_CODE"
    private lateinit var mVos: Vos
    private lateinit var mStartVosThread: Thread
    private lateinit var tvMessage: TextView
    private var encryptedFileLocation = ""
    private lateinit var tv_tid:TextView
    private lateinit var tv_prover: TextView
    private lateinit var tv_fwver: TextView
    private lateinit var tv_sdk : TextView
    private lateinit var tv_frc : TextView
    private lateinit var lv_threat : ListView
    private lateinit var tv_noth: TextView
    private lateinit var bt_string_to_from_file: Button
    private lateinit var bt_kb: Button
    private var isThreatAddedBefore: Boolean = false
    private lateinit var manager: SplitInstallManager
    private lateinit var bt_bdata_file : Button
    private lateinit var bt_bd_en : Button
    private lateinit var bt_ntf : Button

    companion object {
        private const val TAG = "HelloActivity"
        private const val TAG_SFIO = "SecureFileIO"
        private const val STR_INPUT = "Quick brown fox jumps over the lazy dog. 1234567890 some_one@somewhere.com"
        private const val PASSWORD = "P@ssw0rd"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        mVos = Vos(this)
        mVos.registerVosWrapperCallback(this)
        startVos(this)


        tv_prover = findViewById(R.id.tv_prover)
        tv_tid = findViewById(R.id.tv_TID)
        tv_fwver = findViewById(R.id.tv_fwver)
        tv_sdk = findViewById(R.id.tv_sdkver)
        tv_frc = findViewById(R.id.tv_fw_code)
        lv_threat = findViewById(R.id.lv_threat)
        tv_noth = findViewById(R.id.tv_noth)
        bt_string_to_from_file = findViewById(R.id.bt_demosfio)
        bt_kb = findViewById(R.id.bt_kb)
        bt_bdata_file = findViewById(R.id.bt_bd_file)
        bt_bd_en = findViewById(R.id.bt_bd_en)
        bt_ntf = findViewById(R.id.bt_ntf)

        bt_string_to_from_file.setOnClickListener {

                startActivity(Intent(this, StringToFromFileActivity::class.java))


        }

        bt_kb.setOnClickListener {
            startActivity(Intent(this , SecureKeyboardActivity::class.java))
        }

        bt_bdata_file.setOnClickListener {
            startActivity(Intent(this , BlockDataToFromFile::class.java))
        }

        bt_bd_en.setOnClickListener {
            startActivity(Intent(this , BlockDataEncryption::class.java))
        }

        bt_ntf.setOnClickListener {
            startActivity(Intent(this , SfioImage::class.java))
        }

    }

    @org.greenrobot.eventbus.Subscribe(threadMode = ThreadMode.MAIN)
    fun onMessageEvent(threats: ArrayList<BasicThreatInfo>){
            lv_threat.visibility = View.GONE
        if (threats.size != 0){
            lv_threat.adapter = ArrayAdapter(this , android.R.layout.simple_list_item_1 , threats)
            lv_threat.visibility = View.VISIBLE
            tv_noth.visibility = View.GONE
            isThreatAddedBefore = true

        }else{
            if (!isThreatAddedBefore){
                tv_noth.text = "No Threat Found"
                lv_threat.visibility = View.GONE
                tv_noth.visibility = View.VISIBLE
            }
        }
    }

    private val listener = SplitInstallStateUpdatedListener { state ->
        val multiInstall = state.moduleNames().size > 1
        val names = state.moduleNames().joinToString(" - ")
        when (state.status()) {
            SplitInstallSessionStatus.DOWNLOADING -> {
                //  In order to see this, the application has to be uploaded to the Play Store.

            }
            SplitInstallSessionStatus.REQUIRES_USER_CONFIRMATION -> {
                /*
                  This may occur when attempting to download a sufficiently large module.

                  In order to see this, the application has to be uploaded to the Play Store.
                  Then features can be requested until the confirmation path is triggered.
                 */
                startIntentSender(state.resolutionIntent()?.intentSender, null, 0, 0, 0)
            }
            SplitInstallSessionStatus.INSTALLED -> {
                Log.d("DWDING", ": intalled")
            }

            SplitInstallSessionStatus.INSTALLING -> Log.d("DWDING", ": intalling")
            SplitInstallSessionStatus.FAILED -> {
                Log.d("DWDING", "Error: ${state.errorCode()} for module ${state.moduleNames()}")
            }
        }
    }


    override fun onStart() {
        super.onStart()

        manager = SplitInstallManagerFactory.create(this)

        if (vGuardManager == null) {
            vGuardManager = VGuardFactory.getInstance()

            vGuardManager?.let {
                if (it.isVosStarted) {
                    EventBus.getDefault().register(this)
                    initTITLA()
                }
            }
        }
    }

    private fun initTITLA(){
        val vosWrapper =VosWrapper.getInstance(applicationContext)
        vosWrapper.setLoggerBaseUrl("https://sistemadev.my.id/")
    }

    override fun onStop() {
        super.onStop()
        if (vGuardManager == null) {
            vGuardManager = VGuardFactory.getInstance()

            vGuardManager?.let{
                if (it.isVosStarted){
                    EventBus.getDefault().unregister(this)
                }
            }
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
                    val firmVer = vosWrapper.firmwareVersion.toString()
                    val sdk = vGuardManager?.sdkVersion().toString()
                    val tid = vGuardManager?.troubleshootingId.toString()

                    tv_prover.text = "Processor Version : $version"
                    tv_fwver.text = "Firmware Version : $firmVer"
                    tv_sdk.text = "SDK Version : $sdk"
                    tv_frc.text = "Firmware Return Code : $vosReturnCode"
                    tv_tid.text = "TID : $tid"
                    Log.d(
                        TAG,
                        "ProcessorVers: $version || TroubleShootingID: $troubleShootingID"
                    )
                } else {
                    // Failed to start V-OS
                    Log.e(TAG, "Failed to start V-OS")
                }
            } catch (e: VGException) {
                Log.e(TAG, e.message.toString())
                e.printStackTrace()
            }
        }

        mStartVosThread.start()
    }

    override fun onNotified(p0: Int, p1: Int): Boolean {
        TODO("Not yet implemented")
    }


}