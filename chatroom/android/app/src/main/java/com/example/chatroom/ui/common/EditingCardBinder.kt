package com.example.chatroom.ui.common

import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import com.example.chatroom.R
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.participants.AiParticipant
import com.example.chatroom.ui.home.EditingCardData

/**
 * 参与者编辑表单（`item_editing_card.xml`）的绑定逻辑。
 *
 * 原来这段逻辑埋在 `ParticipantAdapter.EditingViewHolder` 里；菜单页的二级卡片直接把
 * `item_editing_card` 动态塞进卡片内部（不用嵌套 RecyclerView），所以抽成可复用的 binder。
 *
 * 绑定约定：
 * - **先灌值、后挂监听**：`setText` / `setSelection` 全部在挂 listener 之前做完，
 *   否则恢复数据的过程本身就会触发一轮「改动」回调
 * - 任何字段改动都会调 [bind] 的 `onEdited`，由调用方决定落盘 / 刷头部
 */
object EditingCardBinder {

    fun bind(
        view: View,
        cardData: EditingCardData,
        onEdited: () -> Unit,
        onRemove: () -> Unit
    ) {
        val typeSpinner: Spinner = view.findViewById(R.id.spinnerType)
        val paramsInput: EditText = view.findViewById(R.id.inputParams)
        val layoutParams: View = view.findViewById(R.id.layoutParams)
        val inputSocketIp: EditText = view.findViewById(R.id.inputSocketIp)
        val layoutSocketIp: View = view.findViewById(R.id.layoutSocketIp)
        val layoutSocketPort: View = view.findViewById(R.id.layoutSocketPort)
        val inputSocketPort: EditText = view.findViewById(R.id.inputSocketPort)
        val layoutSocketPath: View = view.findViewById(R.id.layoutSocketPath)
        val inputSocketPath: EditText = view.findViewById(R.id.inputSocketPath)
        val layoutSockType: View = view.findViewById(R.id.layoutSockType)
        val spinnerSockType: Spinner = view.findViewById(R.id.spinnerSockType)
        val spinnerAiSubType: Spinner = view.findViewById(R.id.spinnerAiSubType)
        val layoutAiSubType: LinearLayout = view.findViewById(R.id.layoutAiSubType)
        val layoutAiVoice: View = view.findViewById(R.id.layoutAiVoice)
        val inputAiVoice: EditText = view.findViewById(R.id.inputAiVoice)
        val layoutEchoDelay: View = view.findViewById(R.id.layoutEchoDelay)
        val inputEchoDelay: EditText = view.findViewById(R.id.inputEchoDelay)
        val inputPtyDevice: EditText = view.findViewById(R.id.inputPtyDevice)
        val layoutPtyDevice: View = view.findViewById(R.id.layoutPtyDevice)
        val inputPtyShell: EditText = view.findViewById(R.id.inputPtyShell)
        val layoutPtyShell: View = view.findViewById(R.id.layoutPtyShell)
        val layoutSerialDevice: View = view.findViewById(R.id.layoutSerialDevice)
        val inputSerialDevice: EditText = view.findViewById(R.id.inputSerialDevice)
        val layoutSerialBaud: View = view.findViewById(R.id.layoutSerialBaud)
        val inputSerialBaud: EditText = view.findViewById(R.id.inputSerialBaud)
        val layoutAiIp: View = view.findViewById(R.id.layoutAiIp)
        val inputAiIp: EditText = view.findViewById(R.id.inputAiIp)
        val layoutAiPort: View = view.findViewById(R.id.layoutAiPort)
        val inputAiPort: EditText = view.findViewById(R.id.inputAiPort)
        val layoutAiApiKey: View = view.findViewById(R.id.layoutAiApiKey)
        val inputAiApiKey: EditText = view.findViewById(R.id.inputAiApiKey)
        val layoutAiModel: View = view.findViewById(R.id.layoutAiModel)
        val inputAiModel: EditText = view.findViewById(R.id.inputAiModel)
        val btnQueryModels: Button = view.findViewById(R.id.btnQueryModels)
        val spinnerAgentSubType: Spinner = view.findViewById(R.id.spinnerAgentSubType)
        val layoutAgentSubType: LinearLayout = view.findViewById(R.id.layoutAgentSubType)
        val layoutAgentAddr: View = view.findViewById(R.id.layoutAgentAddr)
        val inputAgentAddr: EditText = view.findViewById(R.id.inputAgentAddr)
        val layoutAgentPort: View = view.findViewById(R.id.layoutAgentPort)
        val inputAgentPort: EditText = view.findViewById(R.id.inputAgentPort)
        val layoutAgentUsername: View = view.findViewById(R.id.layoutAgentUsername)
        val inputAgentUsername: EditText = view.findViewById(R.id.inputAgentUsername)
        val layoutAgentPassword: View = view.findViewById(R.id.layoutAgentPassword)
        val inputAgentPassword: EditText = view.findViewById(R.id.inputAgentPassword)
        val layoutSshIp: View = view.findViewById(R.id.layoutSshIp)
        val inputSshIp: EditText = view.findViewById(R.id.inputSshIp)
        val layoutSshPort: View = view.findViewById(R.id.layoutSshPort)
        val inputSshPort: EditText = view.findViewById(R.id.inputSshPort)
        val layoutSshUser: View = view.findViewById(R.id.layoutSshUser)
        val inputSshUser: EditText = view.findViewById(R.id.inputSshUser)
        val layoutSshPassword: View = view.findViewById(R.id.layoutSshPassword)
        val inputSshPassword: EditText = view.findViewById(R.id.inputSshPassword)
        val layoutTelnetIp: View = view.findViewById(R.id.layoutTelnetIp)
        val inputTelnetIp: EditText = view.findViewById(R.id.inputTelnetIp)
        val layoutTelnetPort: View = view.findViewById(R.id.layoutTelnetPort)
        val inputTelnetPort: EditText = view.findViewById(R.id.inputTelnetPort)
        val layoutTelnetUser: View = view.findViewById(R.id.layoutTelnetUser)
        val inputTelnetUser: EditText = view.findViewById(R.id.inputTelnetUser)
        val layoutTelnetPassword: View = view.findViewById(R.id.layoutTelnetPassword)
        val inputTelnetPassword: EditText = view.findViewById(R.id.inputTelnetPassword)
        val layoutBluetoothDevice: View = view.findViewById(R.id.layoutBluetoothDevice)
        val spinnerBluetoothDevice: Spinner = view.findViewById(R.id.spinnerBluetoothDevice)
        val btnRefreshBluetoothDevices: Button = view.findViewById(R.id.btnRefreshBluetoothDevices)
        val layoutBluetoothProtocol: View = view.findViewById(R.id.layoutBluetoothProtocol)
        val spinnerBluetoothProtocol: Spinner = view.findViewById(R.id.spinnerBluetoothProtocol)
        val btnCancel: TextView = view.findViewById(R.id.btnCancel)

        fun updateFieldsVisibility() {
            val type = cardData.type
            val isSocket = type == ParticipantType.SOCKET
            val isPty = type == ParticipantType.PTY
            val isSerial = type == ParticipantType.SERIAL
            val isSsh = type == ParticipantType.SSH
            val isTelnet = type == ParticipantType.TELNET
            val isAi = type == ParticipantType.AI
            val isBluetooth = type == ParticipantType.BLUETOOTH
            val isAgent = type == ParticipantType.AGENT
            val isEcho = type == ParticipantType.ECHO
            // 路径仅 WS 协议时才显示
            val isWsPath = isSocket && cardData.sockType == "WS"
            layoutParams.visibility = if (isSocket || isPty || isSerial || isSsh || isTelnet || isAi || isBluetooth || isAgent || isEcho) View.GONE else View.VISIBLE
            layoutSocketIp.visibility = if (isSocket) View.VISIBLE else View.GONE
            layoutSocketPort.visibility = if (isSocket) View.VISIBLE else View.GONE
            layoutSocketPath.visibility = if (isWsPath) View.VISIBLE else View.GONE
            layoutSockType.visibility = if (isSocket) View.VISIBLE else View.GONE
            layoutPtyDevice.visibility = if (isPty) View.VISIBLE else View.GONE
            layoutPtyShell.visibility = if (isPty) View.VISIBLE else View.GONE
            layoutSerialDevice.visibility = if (isSerial) View.VISIBLE else View.GONE
            layoutSerialBaud.visibility = if (isSerial) View.VISIBLE else View.GONE
            layoutBluetoothDevice.visibility = if (isBluetooth) View.VISIBLE else View.GONE
            layoutBluetoothProtocol.visibility = if (isBluetooth) View.VISIBLE else View.GONE
            layoutAiIp.visibility = if (isAi) View.VISIBLE else View.GONE
            layoutAiPort.visibility = if (isAi) View.VISIBLE else View.GONE
            layoutAiApiKey.visibility = if (isAi) View.VISIBLE else View.GONE
            layoutAiModel.visibility = if (isAi) View.VISIBLE else View.GONE
            layoutAiSubType.visibility = if (isAi) View.VISIBLE else View.GONE
            // voice 仅在 AI + tts 时显示
            layoutAiVoice.visibility = if (isAi && cardData.aiSubType == "tts") View.VISIBLE else View.GONE
            // ECHO 延迟仅在 ECHO 时显示
            layoutEchoDelay.visibility = if (isEcho) View.VISIBLE else View.GONE
            layoutAgentSubType.visibility = if (isAgent) View.VISIBLE else View.GONE
            layoutAgentAddr.visibility = if (isAgent) View.VISIBLE else View.GONE
            layoutAgentPort.visibility = if (isAgent) View.VISIBLE else View.GONE
            layoutAgentUsername.visibility = if (isAgent) View.VISIBLE else View.GONE
            layoutAgentPassword.visibility = if (isAgent) View.VISIBLE else View.GONE
            layoutSshIp.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshPort.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshUser.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshPassword.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutTelnetIp.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetPort.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetUser.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetPassword.visibility = if (isTelnet) View.VISIBLE else View.GONE
        }

        // ===== 1) 先灌值（此时还没挂监听，不会触发 onEdited）=====

        typeSpinner.adapter = ArrayAdapter(
            view.context,
            android.R.layout.simple_spinner_dropdown_item,
            ParticipantType.entries.map { "${it.icon} ${it.name}" }
        )
        val typePos = ParticipantType.entries.indexOf(cardData.type)
        if (typePos >= 0) typeSpinner.setSelection(typePos, false)
        updateFieldsVisibility()

        paramsInput.setText(cardData.params)
        inputSocketIp.setText(cardData.socketIp)
        inputSocketPort.setText(cardData.socketPort)
        inputSocketPath.setText(cardData.socketPath)
        inputPtyDevice.setText(cardData.ptyDevice)
        inputPtyShell.setText(cardData.ptyShell)
        inputSerialDevice.setText(cardData.serialDevice)
        inputSerialBaud.setText(cardData.serialBaud)
        inputSshIp.setText(cardData.sshIp)
        inputSshPort.setText(cardData.sshPort)
        inputSshUser.setText(cardData.sshUser)
        inputSshPassword.setText(cardData.sshPassword)
        inputTelnetIp.setText(cardData.telnetIp)
        inputTelnetPort.setText(cardData.telnetPort)
        inputTelnetUser.setText(cardData.telnetUser)
        inputTelnetPassword.setText(cardData.telnetPassword)
        inputAiIp.setText(cardData.aiIp)
        inputAiPort.setText(cardData.aiPort)
        inputAiApiKey.setText(cardData.aiApiKey)
        inputAiModel.setText(cardData.aiModel)
        inputAiVoice.setText(cardData.aiVoice)
        inputEchoDelay.setText(if (cardData.echoDelay == 0.5f) "0.5" else cardData.echoDelay.toString())
        inputAgentAddr.setText(cardData.agentAddr)
        inputAgentPort.setText(cardData.agentPort)
        inputAgentUsername.setText(cardData.agentUsername)
        inputAgentPassword.setText(cardData.agentPassword)

        val sockTypes = listOf("TCP", "UDP", "WS")
        spinnerSockType.adapter = ArrayAdapter(view.context, android.R.layout.simple_spinner_dropdown_item, sockTypes)
        spinnerSockType.setSelection(sockTypes.indexOf(cardData.sockType).coerceAtLeast(0), false)

        val aiSubTypesDisplay = listOf("文本", "语音转文字", "文字转语音")
        val aiSubTypesValue = listOf("text", "stt", "tts")
        spinnerAiSubType.adapter = ArrayAdapter(view.context, android.R.layout.simple_spinner_dropdown_item, aiSubTypesDisplay)
        spinnerAiSubType.setSelection(aiSubTypesValue.indexOf(cardData.aiSubType).coerceAtLeast(0), false)

        val agentSubTypes = listOf("openclaw", "codex", "claude", "gemini", "copilot")
        spinnerAgentSubType.adapter = ArrayAdapter(view.context, android.R.layout.simple_spinner_dropdown_item, agentSubTypes)
        spinnerAgentSubType.setSelection(agentSubTypes.indexOf(cardData.agentSubType).coerceAtLeast(0), false)

        spinnerBluetoothProtocol.adapter = ArrayAdapter(view.context, android.R.layout.simple_spinner_dropdown_item, listOf("SPP", "RFCOMM"))
        spinnerBluetoothProtocol.setSelection(if (cardData.bluetoothProtocol == "RFCOMM") 1 else 0, false)

        // 蓝牙设备 Spinner（初始为空，后续通过系统 API 填充已配对设备）
        spinnerBluetoothDevice.adapter = ArrayAdapter(
            view.context,
            android.R.layout.simple_spinner_dropdown_item,
            listOf("请先刷新设备")
        )

        // ===== 2) 再挂监听 =====

        // 文本字段：统一走一个简化版 TextWatcher（原来 20+ 段匿名类）
        fun EditText.onChanged(block: (String) -> Unit) {
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    block(s.toString())
                    onEdited()
                }
            })
        }

        paramsInput.onChanged { cardData.params = it }
        inputSocketIp.onChanged { cardData.socketIp = it }
        inputSocketPort.onChanged { cardData.socketPort = it }
        inputSocketPath.onChanged { cardData.socketPath = it }
        inputPtyDevice.onChanged { cardData.ptyDevice = it }
        inputPtyShell.onChanged { cardData.ptyShell = it }
        inputSerialDevice.onChanged { cardData.serialDevice = it }
        inputSerialBaud.onChanged { cardData.serialBaud = it }
        inputSshIp.onChanged { cardData.sshIp = it }
        inputSshPort.onChanged { cardData.sshPort = it }
        inputSshUser.onChanged { cardData.sshUser = it }
        inputSshPassword.onChanged { cardData.sshPassword = it }
        inputTelnetIp.onChanged { cardData.telnetIp = it }
        inputTelnetPort.onChanged { cardData.telnetPort = it }
        inputTelnetUser.onChanged { cardData.telnetUser = it }
        inputTelnetPassword.onChanged { cardData.telnetPassword = it }
        inputAiIp.onChanged { cardData.aiIp = it }
        inputAiPort.onChanged { cardData.aiPort = it }
        inputAiApiKey.onChanged { cardData.aiApiKey = it }
        inputAiModel.onChanged { cardData.aiModel = it }
        inputAiVoice.onChanged { cardData.aiVoice = it }
        inputAgentAddr.onChanged { cardData.agentAddr = it }
        inputAgentPort.onChanged { cardData.agentPort = it }
        inputAgentUsername.onChanged { cardData.agentUsername = it }
        inputAgentPassword.onChanged { cardData.agentPassword = it }
        // ECHO 延迟：解析失败回落 0.5
        inputEchoDelay.onChanged { cardData.echoDelay = it.trim().toFloatOrNull() ?: 0.5f }

        typeSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                cardData.type = ParticipantType.entries[pos]
                updateFieldsVisibility()
                onEdited()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        spinnerSockType.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                cardData.sockType = sockTypes[pos]
                updateFieldsVisibility()
                onEdited()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        spinnerAiSubType.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                cardData.aiSubType = aiSubTypesValue[pos]
                // 切了子类型后，voice 字段可能需要显示/隐藏
                updateFieldsVisibility()
                onEdited()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        spinnerAgentSubType.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                cardData.agentSubType = agentSubTypes[pos]
                onEdited()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        spinnerBluetoothProtocol.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                cardData.bluetoothProtocol = if (pos == 0) "SPP" else "RFCOMM"
                onEdited()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // 查询模型按钮（HTTP + 解析委托给 AiParticipant.fetchModels）
        btnQueryModels.setOnClickListener {
            val ip = cardData.aiIp
            val port = cardData.aiPort
            val apiKey = cardData.aiApiKey
            if (ip.isBlank() || port.isBlank()) {
                Toast.makeText(it.context, "请先填 IP 和端口", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            btnQueryModels.isEnabled = false
            btnQueryModels.text = "查询中..."
            AiParticipant.fetchModels(ip, port, apiKey) { code, models, errorMsg ->
                btnQueryModels.isEnabled = true
                btnQueryModels.text = "查询模型"
                when {
                    errorMsg != null ->
                        Toast.makeText(it.context, "查询失败: $errorMsg", Toast.LENGTH_SHORT).show()

                    code != 200 || models.isEmpty() ->
                        Toast.makeText(it.context, "未查到模型（code=$code）", Toast.LENGTH_SHORT).show()

                    else -> android.app.AlertDialog.Builder(it.context)
                        .setTitle("选择模型")
                        .setItems(models.toTypedArray()) { _, which ->
                            val picked = models[which]
                            cardData.aiModel = picked
                            inputAiModel.setText(picked)
                        }
                        .setNegativeButton("取消", null)
                        .show()
                }
            }
        }

        btnRefreshBluetoothDevices.setOnClickListener {
            // TODO: 调用 BluetoothAdapter 获取已配对设备列表
            Toast.makeText(it.context, "刷新蓝牙设备（待实现）", Toast.LENGTH_SHORT).show()
        }

        // 删除这张二级卡片（草稿卡片 = 丢弃；已有会话 = 从会话里删掉该参与者）
        btnCancel.setOnClickListener { onRemove() }
    }
}
