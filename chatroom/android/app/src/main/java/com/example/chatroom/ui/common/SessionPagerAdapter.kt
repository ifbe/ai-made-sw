package com.example.chatroom.ui.common

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.example.chatroom.ui.chat.ChatFragment
import com.example.chatroom.ui.home.HomeFragment

class SessionPagerAdapter(activity: FragmentActivity) : FragmentStateAdapter(activity) {

    // [0] = HomeFragment, [1..n] = ChatFragment per session
    val fragments = mutableListOf<Fragment>()

    init {
        fragments.add(HomeFragment())  // index 0 is always home
    }

    override fun getItemCount(): Int = fragments.size

    override fun createFragment(position: Int): Fragment = fragments[position]

    fun getPageTitle(position: Int): String {
        return when (position) {
            0 -> "🏠 首页"
            else -> "💬 ${position}"
        }
    }

    fun addSession(sessionId: String): Int {
        val index = fragments.size
        val chatFrag = ChatFragment.newInstance(sessionId)
        fragments.add(chatFrag)
        notifyItemInserted(index)
        return index
    }

    fun removeSession(position: Int) {
        if (position < 1) return  // 首页不可删除
        fragments.removeAt(position)
        notifyItemRemoved(position)
    }

    fun isHome(position: Int): Boolean = position == 0
}
