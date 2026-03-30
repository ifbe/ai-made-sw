package com.example.locate.ui.map

import android.content.Context
import com.example.locate.domain.model.User

/**
 * 地图视图抽象接口
 * 可替换为：OSMDroid / Google Maps / 百度地图 等实现
 */
interface MapView {

    /**
     * 显示当前用户位置
     */
    fun showUser(lat: Double, lng: Double, heading: Float)

    /**
     * 显示其他用户位置
     */
    fun showOtherUser(user: User)

    /**
     * 移除其他用户
     */
    fun removeOtherUser(username: String)

    /**
     * 显示所有其他用户
     */
    fun showOtherUsers(users: List<User>)

    /**
     * 显示目标点
     */
    fun showTarget(lat: Double, lng: Double)

    /**
     * 清除目标点
     */
    fun clearTarget()

    /**
     * 移动地图中心到指定位置
     */
    fun moveTo(lat: Double, lng: Double, zoom: Double = 15.0)

    /**
     * 地图点击事件
     * lat/lng: 点击的坐标
     */
    fun setOnMapClickListener(listener: (lat: Double, lng: Double) -> Unit)

    /**
     * 销毁视图
     */
    fun onDestroy()
}
