package com.example.chatroom.ui.home

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.example.chatroom.R
import com.example.chatroom.core.SessionManager
import com.example.chatroom.ui.common.EditingCardBinder
import com.google.android.material.button.MaterialButton

/**
 * 「菜单页」本体（主页 = 它；聊天页左上角 ☰ 打开的是一个 80% 宽的叠加副本）。
 *
 * 结构：
 * ```
 * ┌ 一级卡片（会话）──────────────────────────────────┐
 * │ ×   2609-1301-4310               [回到会话]        │ ← 折叠行：[×] [几排字] [一颗按钮]
 * │     🌐🤖 (2)                                      │   （点中间那几排字 = 展开/折叠）
 * │   ╭──────────────────────────────────────────╮   │ ← 展开：比卡片窄一圈的详情矩形
 * │   │ × [参与者编辑表单]                        │   │   （每个参与者的 × 在它自己左上角）
 * │   │            [+ 添加参与者]                 │   │   （居中，窄条）
 * │   ╰──────────────────────────────────────────╯   │
 * └──────────────────────────────────────────────────┘
 * [               + 新建会话               ]  ← 紧贴最后一张卡片（滚动区内）
 * ```
 * 展开时折叠行**原样不动**，只在下方多出那块矩形。
 *
 * 大加号在**滚动区里紧贴最后一张卡片**，不是钉在页面最底下；点它原地长出一张展开的草稿卡片，
 * 同时自己隐藏（已有草稿就不再显示），所以视觉上就是「加号变成了会话卡片」。
 *
 * 折叠行右边**只有一颗按钮**（`weight=1` 的几排字会把余量吃掉，标题再长也挤不动它），
 * 文案同时承担状态提示与动作：
 * ```
 * 草稿                        →「创建会话」  真正建会话
 * 已有会话 + 不正常(!isSessionUp) →「恢复连接」  断开重连并切过去
 * 已有会话 + 正常               →「回到会话」  切过去
 * ```
 * 所以链路状态一变要重刷折叠行（[refreshConnectionStates]）。
 *
 * 数据来源：
 * - **草稿卡片**（还没创建的会话）→ [SessionDraftStore]（多份菜单实例共享）
 * - **已有会话** → 每次 [reload] 从 [SessionManager] 重建，保证多份实例看到的一致
 *
 * 表单是「编辑即改即存」：已有会话里的字段一改就回写 `SessionManager.updateParticipant`。
 */
class SessionMenuView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    /** 新建会话成功（已落盘）→ 通知外面建 tab / 切过去 */
    var onSessionCreated: ((String) -> Unit)? = null

    /** 点「进入会话」→ 通知外面切到该会话的聊天页 */
    var onEnterSession: ((String) -> Unit)? = null

    /** 点「删除」（已有会话）→ 交给外面走完整关闭流程（断连接 + 清 SessionManager + 关 tab） */
    var onDeleteSession: ((String) -> Unit)? = null

    /** 点「恢复连接」→ 交给外面切到该会话并重连（草稿卡片没有这个按钮） */
    var onReconnectSession: ((String) -> Unit)? = null

    private val cardContainer: LinearLayout
    private val textMenuEmpty: TextView
    private val btnAddSession: View

    /** 展开态 key（草稿 = cardId，已有会话 = sessionId） */
    private val expandedKeys = mutableSetOf<String>()

    private val bindings = mutableListOf<CardBinding>()

    init {
        orientation = VERTICAL
        LayoutInflater.from(context).inflate(R.layout.view_session_menu, this, true)
        cardContainer = findViewById(R.id.cardContainer)
        textMenuEmpty = findViewById(R.id.textMenuEmpty)
        btnAddSession = findViewById(R.id.btnAddSession)
        btnAddSession.setOnClickListener { addDraftCard() }
    }

    // MARK: - 对外

    /** 重新按当前数据（草稿 + SessionManager 已有会话）构建整页 */
    fun reload() {
        cardContainer.removeAllViews()
        bindings.clear()

        val drafts = SessionDraftStore.drafts.toList()
        val sessionIds = SessionManager.getSessionOrder()

        textMenuEmpty.visibility = if (drafts.isEmpty() && sessionIds.isEmpty()) View.VISIBLE else View.GONE

        // 已有会话在前、草稿在后：大加号在列表末尾，点出来的草稿卡片就该出现在同一个位置
        // （顺序反了的话草稿会跑到最顶上，看起来像"凭空在最上面插了一张卡"）
        sessionIds.forEach { sid ->
            val card = SessionCardData(
                sessionId = sid,
                participants = SessionManager.getParticipants(sid)
                    .map { editingCardFromConfig(it, sid) }
                    .toMutableList()
            )
            addCardView(card)
        }
        drafts.forEach { card -> addCardView(card) }

        // 大加号紧跟在最后一张卡片后面；已经有草稿卡片时它自己就藏起来
        // （点它 = 原地长出那张草稿，所以不需要再加第二张）
        btnAddSession.visibility = if (drafts.isEmpty()) View.VISIBLE else View.GONE
    }

    /** 立刻把挂着的防抖落盘刷掉（收起卡片 / 页面要走的时候调） */
    fun flushPendingEdits() {
        SessionManager.persistNow()
    }

    /**
     * 连接状态变了（连上 / 掉线 / 连不上）时调。
     *
     * 会话是否正常现在**只由「恢复连接」按钮体现**（折叠行不再写「未连接」字样），
     * 所以状态一变就要刷按钮的显隐。只刷折叠行，不重建二级表单——否则正在输入的内容会丢焦点。
     */
    fun refreshConnectionStates() {
        bindings.forEach { it.renderHeader() }
    }

    // ===== 卡片 =====

    private fun addCardView(card: SessionCardData) {
        val view = LayoutInflater.from(context).inflate(R.layout.item_session_card, cardContainer, false)
        cardContainer.addView(view)
        val binding = CardBinding(card, view)
        bindings.add(binding)
        binding.render()
    }

    /**
     * 大加号被点：**原地**长出一张草稿会话卡片，并且直接展开。
     *
     * 卡片插在最后（= 大加号原来的位置），`reload()` 里会把大加号自己藏掉
     * （有草稿就不需要再加一张），所以视觉上就是「加号变成了会话卡片」。
     */
    private fun addDraftCard() {
        if (SessionDraftStore.drafts.isNotEmpty()) return
        val card = SessionCardData()
        SessionDraftStore.add(card)
        // 新长出来的草稿默认展开，直接可以填参与者
        expandedKeys.add(card.cardId)
        reload()
    }

    private inner class CardBinding(val card: SessionCardData, val view: View) {

        private val textSessionName: TextView = view.findViewById(R.id.textSessionName)
        private val textSessionMeta: TextView = view.findViewById(R.id.textSessionMeta)
        private val sessionTitleBlock: View = view.findViewById(R.id.sessionTitleBlock)
        private val cardContent: View = view.findViewById(R.id.cardContent)
        private val cardParticipants: LinearLayout = view.findViewById(R.id.cardParticipants)
        private val btnCardPrimary: MaterialButton = view.findViewById(R.id.btnCardPrimary)
        private val btnCardDelete: TextView = view.findViewById(R.id.btnCardDelete)

        fun render() {
            renderParticipants()
            renderExpanded()
            renderHeader()
            // 点中间那几排字 = 展开/折叠（没有单独的展开按钮）
            sessionTitleBlock.setOnClickListener { toggleExpanded() }
            // 左上角 × 是独立按钮，点它不会触发上面那个展开/折叠
            btnCardPrimary.setOnClickListener { onPrimaryClick() }
            btnCardDelete.setOnClickListener { onDeleteClick() }
        }

        /**
         * 折叠行第二排 = 参与者图标串；**不写连接状态**——是否正常由右边那颗按钮的文案体现
         * （不正常显示「恢复连接」）。表单改动 / 链路状态变化后都只刷这里，不重建表单（否则焦点会丢）
         */
        fun renderHeader() {
            val sid = card.sessionId
            textSessionName.text = if (sid == null) "新会话（未创建）" else sessionTimeLabel(sid)

            val count = card.participants.size
            textSessionMeta.text = if (count == 0) {
                "还没有参与者"
            } else {
                val icons = card.participants.joinToString("") { it.type.icon }
                "$icons ($count)"
            }

            renderPrimaryButton()
        }

        /**
         * 右边那颗按钮：**文案同时承担状态提示**，所以状态一变就要重刷（[refreshConnectionStates]）。
         * - 草稿：「创建会话」→ 真正建会话
         * - 已有会话但不正常（掉线 / 连不上 / 重启恢复还没重连）：「恢复连接」→ 断开重连并切过去
         * - 已有会话且正常：「回到会话」→ 切过去
         */
        private fun renderPrimaryButton() {
            val sid = card.sessionId
            btnCardPrimary.text = when {
                sid == null -> "创建会话"
                !SessionManager.isSessionUp(sid) -> "恢复连接"
                else -> "回到会话"
            }
        }

        /** 重建二级卡片列表：参与者编辑表单 + 「添加参与者」卡片 */
        private fun renderParticipants() {
            cardParticipants.removeAllViews()

            card.participants.forEach { data ->
                val item = LayoutInflater.from(context)
                    .inflate(R.layout.item_editing_card, cardParticipants, false)
                cardParticipants.addView(item)
                EditingCardBinder.bind(
                    view = item,
                    cardData = data,
                    onEdited = {
                        val sid = card.sessionId
                        // 已保存的参与者：编辑即改即存（只改内存 + 防抖落盘）
                        if (sid != null) SessionManager.updateParticipant(sid, data.toConfig())
                        onParticipantEdited()
                    },
                    onRemove = { removeParticipant(data) }
                )
            }

            // 「+ 添加参与者」卡片
            val addView = LayoutInflater.from(context)
                .inflate(R.layout.item_add_participant, cardParticipants, false)
            addView.setOnClickListener {
                val sid = card.sessionId
                val data = EditingCardData(sessionId = sid)
                card.participants.add(data)
                if (sid != null) {
                    // 已有会话：立刻落一条 ParticipantConfig，之后这个表单的每次编辑
                    // 才有对象可 updateParticipant（否则新加的参与者会永远存不下去）
                    SessionManager.addParticipant(sid, data.toConfig())
                }
                renderParticipants()
                renderHeader()
            }
            cardParticipants.addView(addView)
        }

        /** 某个表单改了：刷头部图标串；草稿只留在内存，已有会话已由 binder 回写 */
        private fun onParticipantEdited() {
            renderHeader()
        }

        private fun removeParticipant(data: EditingCardData) {
            val sid = card.sessionId
            if (sid != null) {
                // 已有会话：从 SessionManager 里真删（草稿参与者 sessionId 为空，走不到这里）
                SessionManager.removeParticipant(sid, data.id)
            }
            card.participants.removeAll { it.id == data.id }
            renderParticipants()
            renderHeader()
        }

        private fun toggleExpanded() {
            val key = card.expandKey
            if (expandedKeys.contains(key)) {
                expandedKeys.remove(key)
                // 收起时把挂着的防抖落盘刷掉，避免进程这时被杀丢改动
                SessionManager.persistNow()
            } else {
                expandedKeys.add(key)
            }
            renderExpanded()
        }

        private fun renderExpanded() {
            val open = expandedKeys.contains(card.expandKey)
            // 展开只是在折叠行下方多出那块详情矩形，折叠行本身完全不动（也没有箭头要换）
            cardContent.visibility = if (open) View.VISIBLE else View.GONE
        }

        /** 右边那颗按钮：按当前状态决定是「建会话 / 恢复连接 / 回到会话」 */
        private fun onPrimaryClick() {
            val sid = card.sessionId
            when {
                sid == null -> createFromDraft()
                !SessionManager.isSessionUp(sid) -> onReconnectSession?.invoke(sid)
                else -> onEnterSession?.invoke(sid)
            }
        }

        /** 草稿 → 真正建会话：建 session + 落盘参与者 + 通知外面建 tab */
        private fun createFromDraft() {
            if (card.participants.isEmpty()) {
                Toast.makeText(context, "请先添加参与者", Toast.LENGTH_SHORT).show()
                return
            }
            val sessionId = SessionManager.createSession()
            card.participants.forEach { p ->
                SessionManager.addParticipant(sessionId, p.toConfig())
                // 之后这张表单就是「已保存」状态：编辑即改即存
                p.sessionId = sessionId
            }
            SessionDraftStore.remove(card)
            // 把展开态从 cardId 迁到 sessionId，创建后卡片不会莫名收起
            if (expandedKeys.remove(card.cardId)) expandedKeys.add(sessionId)
            SessionManager.persistNow()
            onSessionCreated?.invoke(sessionId)
            reload()
        }

        private fun onDeleteClick() {
            val sid = card.sessionId
            if (sid == null) {
                SessionDraftStore.remove(card)
                reload()
            } else {
                SessionManager.persistNow()
                onDeleteSession?.invoke(sid)
                reload()
            }
        }
    }
}
