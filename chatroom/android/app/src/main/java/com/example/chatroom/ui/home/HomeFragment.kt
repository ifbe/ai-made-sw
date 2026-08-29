package com.example.chatroom.ui.home

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.ParticipantConfig
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.SessionManager
import com.example.chatroom.ui.common.ParticipantAdapter
import com.example.chatroom.ui.common.ParticipantListItem
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton

data class EditingCardData(
    val id: String = java.util.UUID.randomUUID().toString(),
    var type: ParticipantType = ParticipantType.SOCKET,
    var name: String = "",
    var params: String = "",
    var socketIp: String = "",
    var socketPort: String = "",
    var socketPath: String = "/",
    var sockType: String = "TCP",
    var ptyDevice: String = "/dev/ptmx",
    var ptyShell: String = "/system/bin/sh",
    var serialDevice: String = "/dev/ttyS0",
    var serialBaud: String = "115200",
    var sshIp: String = "",
    var sshPort: String = "22",
    var sshUser: String = "",
    var sshPassword: String = "",
    var telnetIp: String = "",
    var telnetPort: String = "23",
    var telnetUser: String = "",
    var telnetPassword: String = "",
    var aiIp: String = "",
    var aiPort: String = "",
    var aiApiKey: String = "",
    var aiModel: String = "",
    /** "text"（默认，OpenAI chat completions）/ "stt"（OpenAI audio transcriptions） / "tts"（OpenAI audio speech） */
    var aiSubType: String = "text",
    /** TTS 专用的 voice 字段，仅 subType=tts 时使用，默认 "alloy" */
    var aiVoice: String = "alloy",
    /** "openclaw"（默认）/ "codex" / "claude" / "gemini" / "copilot" */
    var agentSubType: String = "openclaw",
    var agentAddr: String = "",
    var agentPort: String = "",
    var agentUsername: String = "",
    var agentPassword: String = "",
    /** ECHO 专用：延迟秒数（默认 0.5，可输入浮点） */
    var echoDelay: Float = 0.5f,
    var bluetoothDevice: String = "",
    var bluetoothProtocol: String = "SPP"
)

class HomeFragment : Fragment() {

    private lateinit var recycler: RecyclerView
    private lateinit var adapter: ParticipantAdapter
    private lateinit var textEmpty: TextView

    private val editingCards = mutableListOf<EditingCardData>()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_home, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val toolbar: MaterialToolbar = view.findViewById(R.id.toolbar)
        val btnCreate: MaterialButton = view.findViewById(R.id.btnCreate)
        recycler = view.findViewById(R.id.recyclerParticipants)
        textEmpty = view.findViewById(R.id.textEmpty)

        adapter = ParticipantAdapter(
            onAddClick = { addNewEditingCard() },
            onDeleteClick = { _: ParticipantConfig -> }
        )
        adapter.setEditingCards(editingCards)

        recycler.layoutManager = LinearLayoutManager(requireContext())
        recycler.adapter = adapter

        btnCreate.setOnClickListener {
            // 所见即所得：直接从 editingCards 读当前值（已通过 focusListener 实时更新）
            val validCards = editingCards.filter { it.type != null }
            if (validCards.isEmpty()) {
                Toast.makeText(requireContext(), "请先添加参与者", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val sessionId = SessionManager.createSession()
            validCards.forEach { card ->
                val params: Map<String, String> = when (card.type) {
                    ParticipantType.SOCKET -> {
                        val m = mutableMapOf<String, String>()
                        if (card.socketIp.isNotBlank()) m["ip"] = card.socketIp
                        if (card.socketPort.isNotBlank()) m["port"] = card.socketPort
                        if (card.socketPath.isNotBlank()) m["path"] = card.socketPath
                        if (card.sockType.isNotBlank()) m["sockType"] = card.sockType
                        m
                    }
                    ParticipantType.PTY -> {
                        val m = mutableMapOf<String, String>()
                        if (card.ptyDevice.isNotBlank()) m["device"] = card.ptyDevice
                        if (card.ptyShell.isNotBlank()) m["shell"] = card.ptyShell
                        m
                    }
                    ParticipantType.SERIAL -> {
                        if (card.serialDevice.isNotBlank() && card.serialBaud.isNotBlank()) {
                            mapOf("device" to card.serialDevice, "baud" to card.serialBaud)
                        } else emptyMap()
                    }
                    ParticipantType.SSH -> {
                        val m = mutableMapOf<String, String>()
                        if (card.sshIp.isNotBlank()) m["ip"] = card.sshIp
                        if (card.sshPort.isNotBlank()) m["port"] = card.sshPort
                        if (card.sshUser.isNotBlank()) m["user"] = card.sshUser
                        if (card.sshPassword.isNotBlank()) m["password"] = card.sshPassword
                        m
                    }
                    ParticipantType.TELNET -> {
                        val m = mutableMapOf<String, String>()
                        if (card.telnetIp.isNotBlank()) m["ip"] = card.telnetIp
                        if (card.telnetPort.isNotBlank()) m["port"] = card.telnetPort
                        if (card.telnetUser.isNotBlank()) m["user"] = card.telnetUser
                        if (card.telnetPassword.isNotBlank()) m["password"] = card.telnetPassword
                        m
                    }
                    ParticipantType.AI -> {
                        val m = mutableMapOf<String, String>()
                        if (card.aiIp.isNotBlank()) m["ip"] = card.aiIp
                        if (card.aiPort.isNotBlank()) m["port"] = card.aiPort
                        if (card.aiApiKey.isNotBlank()) m["apiKey"] = card.aiApiKey
                        if (card.aiModel.isNotBlank()) m["model"] = card.aiModel
                        // subType 为默认值 "text" 时不写入（保持与旧 config 兼容）
                        if (card.aiSubType.isNotBlank() && card.aiSubType != "text") m["subType"] = card.aiSubType
                        // voice 仅在 tts 子类型且非默认值时写入（不写默认 "alloy" 避免冗余）
                        if (card.aiSubType == "tts" && card.aiVoice.isNotBlank() && card.aiVoice != "alloy") {
                            m["voice"] = card.aiVoice
                        }
                        m
                    }
                    ParticipantType.AGENT -> {
                        val m = mutableMapOf<String, String>()
                        if (card.agentAddr.isNotBlank()) m["addr"] = card.agentAddr
                        if (card.agentPort.isNotBlank()) m["port"] = card.agentPort
                        if (card.agentUsername.isNotBlank()) m["username"] = card.agentUsername
                        if (card.agentPassword.isNotBlank()) m["password"] = card.agentPassword
                        // subType 为默认值 "openclaw" 时不写入
                        if (card.agentSubType.isNotBlank() && card.agentSubType != "openclaw") m["subType"] = card.agentSubType
                        m
                    }
                    ParticipantType.BLUETOOTH -> {
                        val m = mutableMapOf<String, String>()
                        if (card.bluetoothDevice.isNotBlank()) m["device"] = card.bluetoothDevice
                        if (card.bluetoothProtocol.isNotBlank()) m["protocol"] = card.bluetoothProtocol
                        m
                    }
                    ParticipantType.ECHO -> {
                        // 仅在用户改过默认 0.5 才写入，保持 params 简洁
                        val m = mutableMapOf<String, String>()
                        if (card.echoDelay != 0.5f && card.echoDelay >= 0f) {
                            m["delay"] = card.echoDelay.toString()
                        }
                        m
                    }
                    else -> parseParams(card.params)
                }
                SessionManager.addParticipant(
                    sessionId,
                    ParticipantConfig(
                        type = card.type!!,
                        name = card.name.ifBlank { card.type!!.name },
                        params = params
                    )
                )
            }

            onSessionCreated?.invoke(sessionId)
            editingCards.clear()
            refreshList()
            Toast.makeText(requireContext(), "Session 已创建", Toast.LENGTH_SHORT).show()
        }

        refreshList()
    }

    var onSessionCreated: ((String) -> Unit)? = null

    private fun addNewEditingCard() {
        editingCards.add(EditingCardData())
        refreshList()
    }

    private fun refreshList() {
        val items = mutableListOf<ParticipantListItem>()

        editingCards.forEachIndexed { index, card ->
            items.add(
                ParticipantListItem.EditingCard(
                    id = card.id,
                    onCancel = {
                        val cardId = card.id
                        editingCards.removeAll { it.id == cardId }
                        refreshList()
                    }
                )
            )
        }

        items.add(ParticipantListItem.AddButton(onClick = { addNewEditingCard() }))

        textEmpty.visibility = if (editingCards.isEmpty()) View.VISIBLE else View.GONE
        adapter.submitList(items.toList())
    }

    private fun parseParams(raw: String): Map<String, String> {
        if (raw.isBlank()) return emptyMap()
        return raw.split(" ").associate {
            val parts = it.split(":")
            parts[0] to (parts.getOrNull(1) ?: "")
        }
    }
}
