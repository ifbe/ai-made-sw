package com.example.chatroom.ui.common

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.Spinner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.ParticipantConfig
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.participants.AiParticipant
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
        private val spinnerAiSubType: Spinner = v.findViewById(R.id.spinnerAiSubType)
        private val layoutAiSubType: LinearLayout = v.findViewById(R.id.layoutAiSubType)
        private val layoutAiVoice: View = v.findViewById(R.id.layoutAiVoice)
        private val inputAiVoice: EditText = v.findViewById(R.id.inputAiVoice)
        private val layoutEchoDelay: View = v.findViewById(R.id.layoutEchoDelay)
        private val inputEchoDelay: EditText = v.findViewById(R.id.inputEchoDelay)
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
        private val spinnerAgentSubType: Spinner = v.findViewById(R.id.spinnerAgentSubType)
        private val layoutAgentSubType: LinearLayout = v.findViewById(R.id.layoutAgentSubType)
        private val layoutAgentAddr: View = v.findViewById(R.id.layoutAgentAddr)
        private val inputAgentAddr: EditText = v.findViewById(R.id.inputAgentAddr)
        private val layoutAgentPort: View = v.findViewById(R.id.layoutAgentPort)
        private val inputAgentPort: EditText = v.findViewById(R.id.inputAgentPort)
        private val layoutAgentUsername: View = v.findViewById(R.id.layoutAgentUsername)
        private val inputAgentUsername: EditText = v.findViewById(R.id.inputAgentUsername)
        private val layoutAgentPassword: View = v.findViewById(R.id.layoutAgentPassword)
        private val inputAgentPassword: EditText = v.findViewById(R.id.inputAgentPassword)
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
                ParticipantType.entries.map { "${it.icon} ${it.name}" }
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
            inputAiVoice.setText(cardData.aiVoice)
            inputEchoDelay.setText(if (cardData.echoDelay == 0.5f) "0.5" else cardData.echoDelay.toString())
            inputAgentAddr.setText(cardData.agentAddr)
            inputAgentPort.setText(cardData.agentPort)
            inputAgentUsername.setText(cardData.agentUsername)
            inputAgentPassword.setText(cardData.agentPassword)

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

            // AI 子类型：display label → stored value
            val subTypesDisplay = listOf("文本", "语音转文字", "文字转语音")
            val subTypesValue = listOf("text", "stt", "tts")
            spinnerAiSubType.adapter = android.widget.ArrayAdapter(
                itemView.context,
                android.R.layout.simple_spinner_dropdown_item,
                subTypesDisplay
            )
            val subSelPos = subTypesValue.indexOf(cardData.aiSubType).coerceAtLeast(0)
            spinnerAiSubType.setSelection(subSelPos, false)
            spinnerAiSubType.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    cardData.aiSubType = subTypesValue[pos]
                    // 切了子类型后，voice 字段可能需要显示/隐藏
                    updateFieldsVisibility(cardData)
                }
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }

            // AGENT 子类型（openclaw / codex / claude / gemini / copilot）
            val agentSubTypes = listOf("openclaw", "codex", "claude", "gemini", "copilot")
            spinnerAgentSubType.adapter = android.widget.ArrayAdapter(
                itemView.context,
                android.R.layout.simple_spinner_dropdown_item,
                agentSubTypes
            )
            val agentSubSelPos = agentSubTypes.indexOf(cardData.agentSubType).coerceAtLeast(0)
            spinnerAgentSubType.setSelection(agentSubSelPos, false)
            spinnerAgentSubType.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    cardData.agentSubType = agentSubTypes[pos]
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

            // AI voice（TTS 专用）
            inputAiVoice.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.aiVoice = s.toString()
                }
            })

            // ECHO 延迟（秒）
            inputEchoDelay.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    val raw = s.toString().trim()
                    cardData.echoDelay = raw.toFloatOrNull() ?: 0.5f
                }
            })

            // AGENT 地址
            inputAgentAddr.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.agentAddr = s.toString()
                }
            })

            // AGENT 端口
            inputAgentPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.agentPort = s.toString()
                }
            })

            // AGENT 用户名
            inputAgentUsername.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.agentUsername = s.toString()
                }
            })

            // AGENT 密码
            inputAgentPassword.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.agentPassword = s.toString()
                }
            })

            // 查询模型按钮（HTTP + 解析委托给 AiParticipant.fetchModels）
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
                AiParticipant.fetchModels(ip, port, apiKey) { code, models, errorMsg ->
                    btnQueryModels.isEnabled = true
                    btnQueryModels.text = "查询模型"
                    when {
                        errorMsg != null -> {
                            // 网络/IO 异常
                            android.widget.Toast.makeText(it.context, "查询失败: $errorMsg", android.widget.Toast.LENGTH_SHORT).show()
                        }
                        code != 200 || models.isEmpty() -> {
                            // HTTP 错误 或 200 但没模型：仅 Toast，不弹框
                            android.widget.Toast.makeText(it.context, "未查到模型（code=$code）", android.widget.Toast.LENGTH_SHORT).show()
                        }
                        else -> {
                            // 查到：弹 AlertDialog，点选后回填到 inputAiModel
                            android.app.AlertDialog.Builder(it.context)
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
