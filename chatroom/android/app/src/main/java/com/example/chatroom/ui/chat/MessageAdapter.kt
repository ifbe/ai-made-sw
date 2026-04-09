package com.example.chatroom.ui.chat

import android.graphics.Typeface
import android.text.SpannableStringBuilder
import android.text.style.BackgroundColorSpan
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.text.style.UnderlineSpan
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.Vt100Parser

class MessageAdapter : ListAdapter<Message, RecyclerView.ViewHolder>(MessageDiff()) {

    override fun getItemViewType(position: Int): Int {
        val msg = getItem(position)
        return when {
            msg.isInfo -> VIEW_INFO
            msg.senderId == "self" -> VIEW_SELF
            else -> VIEW_OTHER
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            VIEW_SELF -> SelfViewHolder(inflater.inflate(R.layout.item_message_right, parent, false))
            VIEW_INFO -> InfoViewHolder(inflater.inflate(R.layout.item_message_info, parent, false))
            else -> OtherViewHolder(inflater.inflate(R.layout.item_message_left, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val msg = getItem(position)
        when (holder) {
            is SelfViewHolder -> holder.bind(msg)
            is OtherViewHolder -> holder.bind(msg)
            is InfoViewHolder -> holder.bind(msg)
        }
    }

    class OtherViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        private val textSender: TextView = v.findViewById(R.id.textSender)
        private val textContent: TextView = v.findViewById(R.id.textContent)
        private val imgContent: ImageView = v.findViewById(R.id.imgContent)

        fun bind(msg: Message) {
            textSender.text = "${msg.senderType.icon} ${msg.senderName}"
            bindContent(msg)
        }

        private fun bindContent(msg: Message) {
            if (msg.imageUri != null) {
                textContent.visibility = View.GONE
                imgContent.visibility = View.VISIBLE
            } else {
                textContent.visibility = View.VISIBLE
                imgContent.visibility = View.GONE
                textContent.text = applyVt100Style(msg.content, msg.style)
                textContent.typeface = Typeface.MONOSPACE
            }
        }

        private fun applyVt100Style(text: String, style: com.example.chatroom.core.Vt100Style): SpannableStringBuilder {
            val spans = SpannableStringBuilder()
            val segments = Vt100Parser.parse(text)
            for ((segmentText, segStyle) in segments) {
                val start = spans.length
                spans.append(segmentText)
                if (segStyle.bold) spans.setSpan(StyleSpan(Typeface.BOLD), start, spans.length, 0)
                if (segStyle.underline) spans.setSpan(UnderlineSpan(), start, spans.length, 0)
                if (segStyle.fgColor != android.graphics.Color.BLACK) {
                    spans.setSpan(ForegroundColorSpan(segStyle.fgColor), start, spans.length, 0)
                }
                if (segStyle.bgColor != android.graphics.Color.TRANSPARENT) {
                    spans.setSpan(BackgroundColorSpan(segStyle.bgColor), start, spans.length, 0)
                }
            }
            return spans
        }
    }

    class SelfViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        private val textContent: TextView = v.findViewById(R.id.textContent)
        private val imgContent: ImageView = v.findViewById(R.id.imgContent)

        fun bind(msg: Message) {
            if (msg.imageUri != null) {
                textContent.visibility = View.GONE
                imgContent.visibility = View.VISIBLE
            } else {
                textContent.visibility = View.VISIBLE
                imgContent.visibility = View.GONE
                textContent.text = applyVt100Style(msg.content, msg.style)
            }
        }

        private fun applyVt100Style(text: String, style: com.example.chatroom.core.Vt100Style): SpannableStringBuilder {
            val spans = SpannableStringBuilder()
            val segments = Vt100Parser.parse(text)
            for ((segmentText, segStyle) in segments) {
                val start = spans.length
                spans.append(segmentText)
                if (segStyle.bold) spans.setSpan(StyleSpan(Typeface.BOLD), start, spans.length, 0)
                if (segStyle.underline) spans.setSpan(UnderlineSpan(), start, spans.length, 0)
                if (segStyle.fgColor != android.graphics.Color.BLACK) {
                    spans.setSpan(ForegroundColorSpan(segStyle.fgColor), start, spans.length, 0)
                }
                if (segStyle.bgColor != android.graphics.Color.TRANSPARENT) {
                    spans.setSpan(BackgroundColorSpan(segStyle.bgColor), start, spans.length, 0)
                }
            }
            return spans
        }
    }

    class InfoViewHolder(v: View) : RecyclerView.ViewHolder(v) {
        private val textContent: TextView = v.findViewById(R.id.textContent)

        fun bind(msg: Message) {
            textContent.text = msg.content
            textContent.textSize = 12f
            textContent.setTextColor(android.graphics.Color.parseColor("#AAAAAA"))
            textContent.gravity = Gravity.CENTER_HORIZONTAL
        }
    }

    companion object {
        private const val VIEW_SELF = 0
        private const val VIEW_OTHER = 1
        private const val VIEW_INFO = 2
    }
}

class MessageDiff : DiffUtil.ItemCallback<Message>() {
    override fun areItemsTheSame(oldItem: Message, newItem: Message): Boolean {
        return oldItem.id == newItem.id
    }

    override fun areContentsTheSame(oldItem: Message, newItem: Message): Boolean {
        return oldItem == newItem
    }
}
