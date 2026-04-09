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
    var type: ParticipantType? = null,
    var name: String = "",
    var params: String = "",
    var humanIp: String = "",
    var humanPort: String = "",
    var ptyDevice: String = "/dev/ptmx",
    var ptyShell: String = "/system/bin/sh"
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
                    ParticipantType.HUMAN -> {
                        if (card.humanIp.isNotBlank() && card.humanPort.isNotBlank()) {
                            mapOf("ip" to card.humanIp, "port" to card.humanPort)
                        } else emptyMap()
                    }
                    ParticipantType.PTY -> {
                        val m = mutableMapOf<String, String>()
                        if (card.ptyDevice.isNotBlank()) m["device"] = card.ptyDevice
                        if (card.ptyShell.isNotBlank()) m["shell"] = card.ptyShell
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
                        editingCards.removeAt(index)
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
