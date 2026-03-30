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
     * 显示服务器广播回来的自身位置（调试用，和本地GPS对比）
     */
    fun showServerPosition(lat: Double, lng: Double, heading: Float)

    /**
     * 地图点击事件
     * lat/lng: 点击的坐标
     */
    fun setOnMapClickListener(listener: (lat: Double, lng: Double) -> Unit)

    /**
     * 设置连接状态图标
     * status: 0=连接中(橙), 1=已连接(绿), 2=断开(红)
     * onlineCount: 在线人数（绿色时显示）
     */
    fun setConnectionStatus(status: Int, onlineCount: Int = 0)

    /**
     * 更新目标按钮状态（是否已设置目标）
     */
    fun updateTargetButton(hasTarget: Boolean)

    /**
     * 目标按钮点击回调
     * 回调时传入当前地图中心经纬度
     */
    fun setOnTargetButtonClickListener(listener: (lat: Double, lng: Double) -> Unit)

    /**
     * 连接状态图标点击回调（断开连接时点击可回到登录页）
     */
    fun setOnConnectionStatusClickListener(listener: () -> Unit)

    /**
     * 销毁视图
     */
    fun onDestroy()
}
