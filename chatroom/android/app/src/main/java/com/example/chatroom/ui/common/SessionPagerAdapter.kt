package com.example.chatroom.ui.common

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.example.chatroom.ui.chat.ChatFragment

/**
 * 每个会话一页的 ViewPager2 adapter。
 *
 * **首页不在里面**——菜单页是 Activity 层单独一份（`activity_main.xml` 的 `SessionMenuView`），
 * 启动时整页显示它，会话里点 ☰ 再把它整页叠上来。所以这里的 position 0 就是第一个会话。
 *
 * ## 为什么必须重写 `getItemId` / `containsItem`
 *
 * `FragmentStateAdapter` 默认 `getItemId(position) = position`、`containsItem(id) = id < itemCount`，
 * 这套默认实现**只在「不增删中间项」时成立**。一旦在中间删掉一个会话，后面所有 fragment 的
 * item id 都会错位（例如删掉 position 0 后 itemCount 减一，但后面那个会话的 fragment id 没变）：
 *
 * 1. `gcFragments()` 里 `containsItem(旧id)` 变 false → 把还活着的 fragment 当成过期 fragment
 *    `removeFragment()` 掉——哪怕它正是当前显示的页
 * 2. 而 position 0 仍被已删除会话的 fragment 占着，`ensureFragment(0)` 不会新建，
 *    `placeFragmentInViewHolder` 拿到已销毁的 fragment → `IllegalStateException`
 *
 * 所以 item id 必须**由会话 id 派生**（稳定、与 position 无关），`containsItem` 也要按真实集合判断。
 *
 * 注意：**不能**调 `setHasStableIds()`——`FragmentStateAdapter` 自己开了稳定 id，
 * 并且把它 override 成 final 直接抛 `UnsupportedOperationException`。
 *
 * 另一个连带影响：`FragmentStateAdapter` 加 fragment 用的 tag 是 `"f" + itemId`，
 * 所以 MainActivity 找 fragment 也必须用 `"f" + itemIdForSession(sessionId)`，不能再用 position。
 */
class SessionPagerAdapter(activity: FragmentActivity) : FragmentStateAdapter(activity) {

    /** 与 position 一一对应的 ChatFragment（position 0 = 第一个会话） */
    val fragments = mutableListOf<Fragment>()

    /** 与 [fragments] 一一对应的稳定 item id */
    private val itemIds = mutableListOf<Long>()

    override fun getItemCount(): Int = fragments.size

    override fun getItemId(position: Int): Long = itemIds[position]

    override fun containsItem(itemId: Long): Boolean = itemIds.contains(itemId)

    override fun createFragment(position: Int): Fragment = fragments[position]

    /**
     * @return 新会话所在的 position
     */
    fun addSession(sessionId: String): Int {
        val index = fragments.size
        fragments.add(ChatFragment.newInstance(sessionId))
        itemIds.add(itemIdForSession(sessionId))
        notifyItemInserted(index)
        return index
    }

    fun removeSession(position: Int) {
        if (position < 0 || position >= fragments.size) return
        fragments.removeAt(position)
        itemIds.removeAt(position)
        notifyItemRemoved(position)
    }

    /** FragmentStateAdapter 用的 fragment tag（`"f" + itemId`），MainActivity 靠它找回 fragment */
    fun fragmentTagForSession(sessionId: String): String = "f" + itemIdForSession(sessionId)

    companion object {
        /**
         * 会话 → 稳定 item id。
         *
         * 直接拿 sessionId 的 hash：同一会话在任何时候都得到同一个 id，且与它在列表里的位置无关
         * （位置会随增删变化，id 不会）。
         */
        fun itemIdForSession(sessionId: String): Long = sessionId.hashCode().toLong()
    }
}
