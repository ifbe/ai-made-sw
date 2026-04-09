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
        private val inputIp: EditText = v.findViewById(R.id.inputIp)
        private val layoutIp: View = v.findViewById(R.id.layoutIp)
        private val inputPort: EditText = v.findViewById(R.id.inputPort)
        private val layoutPort: View = v.findViewById(R.id.layoutPort)
        private val inputPtyDevice: EditText = v.findViewById(R.id.inputPtyDevice)
        private val layoutPtyDevice: View = v.findViewById(R.id.layoutPtyDevice)
        private val inputPtyShell: EditText = v.findViewById(R.id.inputPtyShell)
        private val layoutPtyShell: View = v.findViewById(R.id.layoutPtyShell)
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
            updateFieldsVisibility(cardData.type)

            // 恢复内容
            paramsInput.setText(cardData.params)
            inputIp.setText(cardData.humanIp)
            inputPort.setText(cardData.humanPort)
            inputPtyDevice.setText(cardData.ptyDevice)
            inputPtyShell.setText(cardData.ptyShell)

            // 类型切换
            typeSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, selPos: Int, id: Long) {
                    val t = ParticipantType.entries[selPos]
                    cardData.type = t
                    updateFieldsVisibility(t)
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
            inputIp.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.humanIp = s.toString()
                }
            })

            // 端口
            inputPort.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    cardData.humanPort = s.toString()
                }
            })

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

            btnCancel.setOnClickListener {
                editingCards.remove(cardData)
                item.onCancel()
            }
        }

        private fun updateFieldsVisibility(type: ParticipantType?) {
            val isHuman = type == ParticipantType.HUMAN
            val isPty = type == ParticipantType.PTY
            layoutParams.visibility = if (isHuman || isPty) View.GONE else View.VISIBLE
            layoutIp.visibility = if (isHuman) View.VISIBLE else View.GONE
            layoutPort.visibility = if (isHuman) View.VISIBLE else View.GONE
            layoutPtyDevice.visibility = if (isPty) View.VISIBLE else View.GONE
            layoutPtyShell.visibility = if (isPty) View.VISIBLE else View.GONE
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
