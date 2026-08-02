package com.example.chatroom.ui.common

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.ImageButton
import android.widget.Spinner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.ParticipantConfig
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.ui.home.EditingCardData

sealed class ParticipantListItem {
    data class AddButton(val onClick: () -> Unit) : ParticipantListItem()
    data class Config(val config: ParticipantConfig, val onDelete: () -> Unit) : ParticipantListItem()
    data class EditingCard(
        val id: String,
        val onCancel: () -> Unit
    ) : ParticipantListItem()
}

class ParticipantAdapter(
    private val onAddClick: () -> Unit,
    private val onDeleteClick: (ParticipantConfig) -> Unit
) : ListAdapter<ParticipantListItem, RecyclerView.ViewHolder>(Diff()) {

    // editingCards 由 HomeFragment 提供引用，数据存在这里
    private var editingCards: MutableList<EditingCardData> = mutableListOf()

    fun setEditingCards(cards: MutableList<EditingCardData>) {
        editingCards = cards
    }

    override fun getItemViewType(position: Int): Int = when (getItem(position)) {
        is ParticipantListItem.AddButton -> VIEW_ADD
        is ParticipantListItem.Config -> VIEW_CONFIG
        is ParticipantListItem.EditingCard -> VIEW_EDITING
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            VIEW_ADD -> AddViewHolder(inflater.inflate(R.layout.item_add_participant, parent, false))
            VIEW_CONFIG -> ConfigViewHolder(inflater.inflate(R.layout.item_participant_card, parent, false))
            VIEW_EDITING -> EditingViewHolder(inflater.inflate(R.layout.item_editing_card, parent, false))
            else -> throw IllegalArgumentException("unknown view type")
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = getItem(position)) {
            is ParticipantListItem.AddButton -> (holder as AddViewHolder).bind(item.onClick)
            is ParticipantListItem.Config -> (holder as ConfigViewHolder).bind(item.config, item.onDelete)
            is ParticipantListItem.EditingCard -> (holder as EditingViewHolder).bind(item, editingCards)
        }
    }

    class AddViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        fun bind(onClick: () -> Unit) {
            itemView.setOnClickListener { onClick() }
        }
    }

    class ConfigViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        private val textIcon: android.widget.TextView = v.findViewById(R.id.textIcon)
        private val textName: android.widget.TextView = v.findViewById(R.id.textName)
        private val textParams: android.widget.TextView = v.findViewById(R.id.textParams)
        private val btnDelete: ImageButton = v.findViewById(R.id.btnDelete)

        fun bind(config: ParticipantConfig, onDelete: () -> Unit) {
            textIcon.text = config.type.icon
            textName.text = config.name
            textParams.text = config.params.entries.joinToString(" ") { "${it.key}=${it.value}" }
            btnDelete.setOnClickListener { onDelete() }
        }
    }

    class EditingViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        private val typeSpinner: Spinner = v.findViewById(R.id.spinnerType)
        private val paramsInput: EditText = v.findViewById(R.id.inputParams)
        private val layoutParams: View = v.findViewById(R.id.layoutParams)
        private val inputSocketIp: EditText = v.findViewById(R.id.inputSocketIp)
        private val layoutSocketIp: View = v.findViewById(R.id.layoutSocketIp)
        private val layoutSocketPort: View = v.findViewById(R.id.layoutSocketPort)
        private val inputSocketPort: EditText = v.findViewById(R.id.inputSocketPort)
        private val layoutSocketPath: View = v.findViewById(R.id.layoutSocketPath)
        private val inputSocketPath: EditText = v.findViewById(R.id.inputSocketPath)
        private val layoutSockType: View = v.findViewById(R.id.layoutSockType)
        private val spinnerSockType: Spinner = v.findViewById(R.id.spinnerSockType)
        private val inputPtyDevice: EditText = v.findViewById(R.id.inputPtyDevice)
        private val layoutPtyDevice: View = v.findViewById(R.id.layoutPtyDevice)
        private val inputPtyShell: EditText = v.findViewById(R.id.inputPtyShell)
        private val layoutPtyShell: View = v.findViewById(R.id.layoutPtyShell)
        private val layoutSerialDevice: View = v.findViewById(R.id.layoutSerialDevice)
        private val inputSerialDevice: EditText = v.findViewById(R.id.inputSerialDevice)
        private val layoutSerialBaud: View = v.findViewById(R.id.layoutSerialBaud)
        private val inputSerialBaud: EditText = v.findViewById(R.id.inputSerialBaud)
        private val layoutAiIp: View = v.findViewById(R.id.layoutAiIp)
        private val inputAiIp: EditText = v.findViewById(R.id.inputAiIp)
        private val layoutAiPort: View = v.findViewById(R.id.layoutAiPort)
        private val inputAiPort: EditText = v.findViewById(R.id.inputAiPort)
        private val layoutAiApiKey: View = v.findViewById(R.id.layoutAiApiKey)
        private val inputAiApiKey: EditText = v.findViewById(R.id.inputAiApiKey)
        private val layoutAiModel: View = v.findViewById(R.id.layoutAiModel)
        private val inputAiModel: EditText = v.findViewById(R.id.inputAiModel)
        private val btnQueryModels: android.widget.Button = v.findViewById(R.id.btnQueryModels)
        private val layoutAiModels: View = v.findViewById(R.id.layoutAiModels)
        private val spinnerAiModels: Spinner = v.findViewById(R.id.spinnerAiModels)
        private val layoutSshIp: View = v.findViewById(R.id.layoutSshIp)
        private val inputSshIp: EditText = v.findViewById(R.id.inputSshIp)
        private val layoutSshPort: View = v.findViewById(R.id.layoutSshPort)
        private val inputSshPort: EditText = v.findViewById(R.id.inputSshPort)
        private val layoutSshUser: View = v.findViewById(R.id.layoutSshUser)
        private val inputSshUser: EditText = v.findViewById(R.id.inputSshUser)
        private val layoutSshPassword: View = v.findViewById(R.id.layoutSshPassword)
        private val inputSshPassword: EditText = v.findViewById(R.id.inputSshPassword)
        private val layoutTelnetIp: View = v.findViewById(R.id.layoutTelnetIp)
        private val inputTelnetIp: EditText = v.findViewById(R.id.inputTelnetIp)
        private val layoutTelnetPort: View = v.findViewById(R.id.layoutTelnetPort)
        private val inputTelnetPort: EditText = v.findViewById(R.id.inputTelnetPort)
        private val layoutTelnetUser: View = v.findViewById(R.id.layoutTelnetUser)
        private val inputTelnetUser: EditText = v.findViewById(R.id.inputTelnetUser)
        private val layoutTelnetPassword: View = v.findViewById(R.id.layoutTelnetPassword)
        private val inputTelnetPassword: EditText = v.findViewById(R.id.inputTelnetPassword)
        private val layoutBluetoothDevice: View = v.findViewById(R.id.layoutBluetoothDevice)
        private val spinnerBluetoothDevice: Spinner = v.findViewById(R.id.spinnerBluetoothDevice)
        private val btnRefreshBluetoothDevices: android.widget.Button = v.findViewById(R.id.btnRefreshBluetoothDevices)
        private val layoutBluetoothProtocol: View = v.findViewById(R.id.layoutBluetoothProtocol)
        private val spinnerBluetoothProtocol: Spinner = v.findViewById(R.id.spinnerBluetoothProtocol)
        private val btnCancel: ImageButton = v.findViewById(R.id.btnCancel)

        fun bind(item: ParticipantListItem.EditingCard, editingCards: MutableList<EditingCardData>) {
            val cardData = editingCards.find { it.id == item.id } ?: return

            typeSpinner.adapter = ArrayAdapter(
                itemView.context,
                android.R.layout.simple_spinner_dropdown_item,
                ParticipantType.entries.filter { it != ParticipantType.USER }.map { "${it.icon} ${it.name}" }
            )

            // 恢复类型选择
            val pos = cardData.type?.let { ParticipantType.entries.indexOf(it) } ?: -1
            if (pos >= 0) typeSpinner.setSelection(pos, false)
            updateFieldsVisibility(cardData)

            // 恢复内容
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

            // 蓝牙协议 Spinner
            spinnerBluetoothProtocol.adapter = ArrayAdapter(
                itemView.context,
                android.R.layout.simple_spinner_dropdown_item,
                listOf("SPP", "RFCOMM")
            )
            // 恢复协议选择
            val protoPos = cardData.bluetoothProtocol?.let { if (it == "SPP") 0 else 1 } ?: 0
            spinnerBluetoothProtocol.setSelection(protoPos, false)

            // 蓝牙设备 Spinner（初始为空，后续通过系统 API 填充已配对设备）
            spinnerBluetoothDevice.adapter = ArrayAdapter(
                itemView.context,
                android.R.layout.simple_spinner_dropdown_item,
                listOf("请先刷新设备")
            )

            // 类型切换
            typeSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, selPos: Int, id: Long) {
                    val t = ParticipantType.entries[selPos]
                    cardData.type = t
                    updateFieldsVisibility(cardData)
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }

            // 通用参数
            paramsInput.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.params = s.toString()
                }
            })

            // IP
            inputSocketIp.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.socketIp = s.toString()
                }
            })

            // 端口
            inputSocketPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.socketPort = s.toString()
                }
            })

            // SOCKET 路径
            inputSocketPath.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.socketPath = s.toString()
                }
            })

            // SOCKET 协议类型
            val sockTypes = listOf("TCP", "UDP", "WS")
            val sockAdapter = android.widget.ArrayAdapter(itemView.context, android.R.layout.simple_spinner_dropdown_item, sockTypes)
            spinnerSockType.adapter = sockAdapter
            val selPos = sockTypes.indexOf(cardData.sockType).coerceAtLeast(0)
            spinnerSockType.setSelection(selPos, false)
            spinnerSockType.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    cardData.sockType = sockTypes[pos]
                    updateFieldsVisibility(cardData)
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }

            // PTY 设备
            inputPtyDevice.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.ptyDevice = s.toString()
                }
            })

            // PTY Shell
            inputPtyShell.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.ptyShell = s.toString()
                }
            })

            // SERIAL 设备
            inputSerialDevice.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.serialDevice = s.toString()
                }
            })

            // SERIAL 波特率
            inputSerialBaud.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.serialBaud = s.toString()
                }
            })

            // SSH IP
            inputSshIp.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.sshIp = s.toString()
                }
            })

            // SSH 端口
            inputSshPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.sshPort = s.toString()
                }
            })

            // SSH 用户
            inputSshUser.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.sshUser = s.toString()
                }
            })

            // AI IP
            inputAiIp.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.aiIp = s.toString()
                }
            })

            // AI 端口
            inputAiPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.aiPort = s.toString()
                }
            })

            // AI API Key
            inputAiApiKey.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.aiApiKey = s.toString()
                }
            })

            // AI 模型
            inputAiModel.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.aiModel = s.toString()
                }
            })

            // 查询模型按钮
            btnQueryModels.setOnClickListener {
                val ip = cardData.aiIp
                val port = cardData.aiPort
                val apiKey = cardData.aiApiKey
                if (ip.isBlank() || port.isBlank()) {
                    android.widget.Toast.makeText(it.context, "请先填 IP 和端口", android.widget.Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                btnQueryModels.isEnabled = false
                btnQueryModels.text = "查询中..."
                Thread({
                    try {
                        val url = java.net.URL("http://" + ip + ":" + port + "/v1/models")
                        val conn = url.openConnection() as java.net.HttpURLConnection
                        conn.requestMethod = "GET"
                        conn.setRequestProperty("Authorization", "Bearer " + apiKey)
                        conn.connectTimeout = 5000
                        conn.readTimeout = 10000
                        val code = conn.responseCode
                        val body = if (code == 200) java.io.BufferedReader(java.io.InputStreamReader(conn.inputStream)).readText() else ""
                        conn.disconnect()

                        val models = mutableListOf<String>()
                        if (code == 200) {
                            val json = org.json.JSONObject(body)
                            val data = json.optJSONArray("data")
                            if (data != null) {
                                for (i in 0 until data.length()) {
                                    val m = data.getJSONObject(i).optString("id", "")
                                    if (m.isNotBlank()) models.add(m)
                                }
                            }
                        }

                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            btnQueryModels.isEnabled = true
                            btnQueryModels.text = "查询模型"
                            if (models.isEmpty()) {
                                android.widget.Toast.makeText(it.context, "未查到模型（code=" + code + ")", android.widget.Toast.LENGTH_SHORT).show()
                                layoutAiModels.visibility = View.GONE
                            } else {
                                val adapter = android.widget.ArrayAdapter(it.context, android.R.layout.simple_spinner_dropdown_item, models)
                                spinnerAiModels.adapter = adapter
                                layoutAiModels.visibility = View.VISIBLE
                            }
                        }
                    } catch (e: Exception) {
                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            btnQueryModels.isEnabled = true
                            btnQueryModels.text = "查询模型"
                            android.widget.Toast.makeText(it.context, "查询失败: " + e.message, android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }, "QueryModels").start()
            }

            // 模型 Spinner 选择
            spinnerAiModels.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    val model = parent?.getItemAtPosition(pos) as? String ?: return
                    cardData.aiModel = model
                    inputAiModel.setText(model)
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }

            // SSH 密码
            inputSshPassword.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.sshPassword = s.toString()
                }
            })

            // TELNET IP
            inputTelnetIp.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.telnetIp = s.toString()
                }
            })

            // TELNET 端口
            inputTelnetPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.telnetPort = s.toString()
                }
            })

            // TELNET 用户
            inputTelnetUser.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.telnetUser = s.toString()
                }
            })

            // TELNET 密码
            inputTelnetPassword.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.telnetPassword = s.toString()
                }
            })

            // 蓝牙协议选择
            spinnerBluetoothProtocol.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    cardData.bluetoothProtocol = if (pos == 0) "SPP" else "RFCOMM"
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }

            // 蓝牙设备刷新按钮
            btnRefreshBluetoothDevices.setOnClickListener {
                // TODO: 调用 BluetoothAdapter 获取已配对设备列表
                android.widget.Toast.makeText(it.context, "刷新蓝牙设备（待实现）", android.widget.Toast.LENGTH_SHORT).show()
            }

            btnCancel.setOnClickListener {
                val id = cardData.id
                editingCards.removeAll { it.id == id }
                item.onCancel()
            }
        }

        private fun updateFieldsVisibility(cardData: EditingCardData) {
            val type = cardData.type
            val isSocket = type == ParticipantType.SOCKET
            val isPty = type == ParticipantType.PTY
            val isSerial = type == ParticipantType.SERIAL
            val isSsh = type == ParticipantType.SSH
            val isTelnet = type == ParticipantType.TELNET
            val isAi = type == ParticipantType.AI
            val isBluetooth = type == ParticipantType.BLUETOOTH
            // 路径仅 WS 协议时才显示
            val isWsPath = isSocket && cardData.sockType == "WS"
            layoutParams.visibility = if (isSocket || isPty || isSerial || isSsh || isTelnet || isAi || isBluetooth) View.GONE else View.VISIBLE
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
            layoutAiModels.visibility = View.GONE
            layoutSshIp.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshPort.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshUser.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutSshPassword.visibility = if (isSsh) View.VISIBLE else View.GONE
            layoutTelnetIp.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetPort.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetUser.visibility = if (isTelnet) View.VISIBLE else View.GONE
            layoutTelnetPassword.visibility = if (isTelnet) View.VISIBLE else View.GONE
        }
    }

    companion object {
        private const val VIEW_ADD = 0
        private const val VIEW_CONFIG = 1
        private const val VIEW_EDITING = 2
    }
}

class Diff : DiffUtil.ItemCallback<ParticipantListItem>() {
    override fun areItemsTheSame(oldItem: ParticipantListItem, newItem: ParticipantListItem): Boolean {
        return when {
            oldItem is ParticipantListItem.AddButton && newItem is ParticipantListItem.AddButton -> true
            oldItem is ParticipantListItem.Config && newItem is ParticipantListItem.Config ->
                oldItem.config.id == newItem.config.id
            oldItem is ParticipantListItem.EditingCard && newItem is ParticipantListItem.EditingCard ->
                oldItem.id == newItem.id
            else -> false
        }
    }

    override fun areContentsTheSame(oldItem: ParticipantListItem, newItem: ParticipantListItem): Boolean {
        return oldItem == newItem
    }
}
