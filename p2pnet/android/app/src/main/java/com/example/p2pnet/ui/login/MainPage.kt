package com.example.p2pnet.ui.login

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.focus.FocusManager
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.ui.Page
import android.os.Build
import android.graphics.Rect
import android.view.WindowManager
import kotlinx.coroutines.delay
import kotlin.math.abs
import kotlin.math.roundToInt
import kotlin.random.Random

/** 其他人节点的高度固定；宽度改为按内容自适应，下面这个常量只当作「量到真实宽度之前」的估算值 */
private val PeerNodeWidth = 220.dp
private val PeerNodeHeight = 58.dp
private val PeerActionHeight = 32.dp

/** 节点里“名字(ip:port)”那一行（拖动把手）的中心，距卡片顶部的距离，连线连到这里 */
private val PeerTitleCenterY = 10.dp

/** “我”卡片贴底时的空隙（按要求边距为 0） */
private val MeCardBottomMargin = 0.dp

/** 其他人卡片默认位置的 y 取值范围（相对可用高度），只落在上半区域 */
private const val PeerYRange = 0.5f

/** UDP socket 卡片的高度固定；宽度按内容自适应，常量只作为量到宽度之前的估算值 */
private val UdpSocketCardWidth = 190.dp
private val UdpSocketCardHeight = 48.dp
private val UdpSocketGap = 24.dp

/** direct 卡片结果行（可达地址列表）的最大宽度：卡片宽度是内容自适应，不封顶会被长列表撑爆 */
private val DirectNoteMaxWidth = 240.dp

/** “我”卡片里输入框的最小宽度（避免纯内容自适应时输入区太窄） */
private val CompactFieldMinWidth = 140.dp

/** 卡片与服务器连线：未登录=白色虚线，已登录 / 其他人=绿色实线，统一粗细不加粗 */
private val LinkGreen = Color(0xFF4CAF50)
private val LinkStrokeWidth = 2.dp
private val LinkDashOn = 8.dp
private val LinkDashOff = 6.dp

/** “我”卡片里输入框的高度（原来 Material 默认 56dp，这里砍一半） */
private val CompactFieldHeight = 28.dp

/** 输入框标签放在框外时占的固定宽度，保证多行标签左侧对齐 */
private val FieldLabelWidth = 40.dp

/** 节点标题：有 ip/port 时显示成 “我(1.2.3.4:5678)” 这种形式 */
private fun nodeLabel(name: String, ip: String, port: Int): String =
    if (ip.isNotEmpty() || port != 0) "$name($ip:$port)" else name

@Composable
fun MainPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val focusManager = LocalFocusManager.current

    // 日志浮层：false = 折叠（只剩右下角按钮），true = 展开（90% 屏幕）
    var logExpanded by remember { mutableStateOf(false) }
    val logProgress by animateFloatAsState(
        targetValue = if (logExpanded) 1f else 0f,
        animationSpec = tween(durationMillis = 260, easing = FastOutSlowInEasing)
    )

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize()) {
            // ── Block 1: connection（内容不变，只调整了外边距）──
            ConnectionCard(
                uiState = uiState,
                viewModel = viewModel,
                focusManager = focusManager,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 4.dp, end = 4.dp, top = 8.dp)
            )

            // ── 自由层：连接线 + “我”卡片 + 随机分布的其他人节点（都可拖动）──
            FreeLayer(
                uiState = uiState,
                viewModel = viewModel,
                focusManager = focusManager,
                showLink = uiState.isConnected,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            )

            /* ── Block 3: peer（按要求注释掉）
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    OutlinedTextField(
                        value = uiState.targetUsername,
                        onValueChange = viewModel::onTargetUsernameChange,
                        label = { Text("对方用户名") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { viewModel.onList() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Text("list")
                        }
                        OutlinedButton(
                            onClick = { /* wghelp 已移除：wg 改在 socket 卡片上选 */ },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.secondary
                            )
                        ) {
                            Text("wghelp")
                        }
                        OutlinedButton(
                            onClick = { viewModel.onUdp() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.tertiary
                            )
                        ) {
                            Text("udp")
                        }
                        OutlinedButton(
                            onClick = { viewModel.navigateTo(Page.Chat(uiState.targetUsername)) },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("tcp")
                        }
                    }
                }
            }
            */
        }

        // ── 日志浮层（浮于最上层）──
        // 折叠 / 展开共用 progress：1 = 展开到 90%，0 = 缩回右下角按钮
        if (logProgress > 0.001f) {
            // 背景遮罩，随折叠一起淡出；同时吞掉所有触摸，
            // 避免日志展开时误点到/拖到下面的卡片（日志面板本身在遮罩之上，不受影响）
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.55f * logProgress))
                    .pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                awaitPointerEvent().changes.forEach { it.consume() }
                            }
                        }
                    }
            )

            AppLogPanel(
                messages = uiState.messages,
                onClear = viewModel::clearMessages,
                onClose = { logExpanded = false },
                modifier = Modifier
                    .align(Alignment.Center)
                    .fillMaxSize(0.9f)
                    .graphicsLayer {
                        val p = logProgress
                        alpha = p
                        // 以面板右下角（≈ 屏幕右下角按钮）为原点缩放，形成从按钮放大 / 缩回按钮的动画
                        transformOrigin = TransformOrigin(1f, 1f)
                        scaleX = 0.08f + 0.92f * p
                        scaleY = 0.08f + 0.92f * p
                    }
            )
        }

        // ── 右下角“日志”按钮：折叠或展开时始终显示 ──
        Box(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp)
                .shadow(8.dp, RoundedCornerShape(24.dp))
                .clip(RoundedCornerShape(24.dp))
                .background(
                    if (logExpanded) MaterialTheme.colorScheme.tertiaryContainer
                    else MaterialTheme.colorScheme.primaryContainer
                )
                .clickable { logExpanded = !logExpanded }
                .padding(horizontal = 20.dp, vertical = 12.dp)
        ) {
            Text(
                text = "日志",
                style = MaterialTheme.typography.labelLarge,
                color = if (logExpanded) MaterialTheme.colorScheme.onTertiaryContainer
                else MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

// MARK: - Block 1: 服务器卡片（内容不变）

@Composable
private fun ConnectionCard(
    uiState: LoginUiState,
    viewModel: LoginViewModel,
    focusManager: FocusManager,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text("ws", style = MaterialTheme.typography.bodyMedium)
                    Switch(
                        checked = uiState.useWss,
                        onCheckedChange = viewModel::onUseWssChange,
                        modifier = Modifier.height(24.dp)
                    )
                    Text("wss", style = MaterialTheme.typography.bodyMedium)
                }
                CompactField(
                    value = uiState.serverHost,
                    onValueChange = viewModel::onServerHostChange,
                    label = "服务器",
                    enabled = !uiState.loading,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Uri,
                        imeAction = ImeAction.Next
                    ),
                    keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Right) }),
                    modifier = Modifier.weight(1f)
                )
                CompactField(
                    value = uiState.serverPort,
                    onValueChange = viewModel::onServerPortChange,
                    label = "端口",
                    enabled = !uiState.loading,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Number,
                        imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(onDone = {
                        focusManager.clearFocus()
                        if (!uiState.isConnected) viewModel.onConnect()
                    }),
                    modifier = Modifier.width(92.dp)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    if (uiState.isConnected) {
                        viewModel.onDisconnect()
                    } else {
                        viewModel.onConnect()
                    }
                },
                enabled = !uiState.loading,
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 0.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(32.dp)
            ) {
                Text(
                    text = if (uiState.isConnected) "已连接，点我断开" else "未连接，点我连接",
                    fontSize = 12.sp,
                    maxLines = 1
                )
            }
        }
    }
}

// MARK: - Block 2: “我”卡片

@Composable
private fun MeCard(
    uiState: LoginUiState,
    viewModel: LoginViewModel,
    focusManager: FocusManager,
    onDrag: (Offset) -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.clip(RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            // 宽度 = 内部最宽那一行（自适应）
            modifier = Modifier.width(IntrinsicSize.Max),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // 标题：未 list 时只有“我”，list 之后变成 “我(ip:port)”；这一行也是拖动把手
            Text(
                text = nodeLabel("我", uiState.myIp, uiState.myPort),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .dragHandle(onDrag)
            )

            // 用户名在上，密码在下；标签挪到输入框外面的左侧
            CompactField(
                value = uiState.username,
                onValueChange = viewModel::onUsernameChange,
                label = "用户名",
                enabled = !uiState.loading,
                labelOutside = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
                modifier = Modifier.widthIn(min = CompactFieldMinWidth)
            )
            CompactField(
                value = uiState.password,
                onValueChange = viewModel::onPasswordChange,
                label = "密码",
                enabled = !uiState.loading,
                isPassword = true,
                labelOutside = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = {
                    focusManager.clearFocus()
                    viewModel.onLogin()
                }),
                modifier = Modifier.widthIn(min = CompactFieldMinWidth)
            )

            // 我的 ip / port 已经并在上面的标题里，这里不再单独显示

            uiState.error?.let { error ->
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            // 左边登录/退出，右边 list（list 不依赖登录，可反复点）
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = {
                        if (uiState.isLoggedIn) {
                            viewModel.onLogout()
                        } else {
                            viewModel.onLogin()
                        }
                    },
                    // 只要连着就能按：密码为空时由 onLogin() 给出“请输入用户名和密码”的提示，
                    // 避免出现按钮灰着、点不了的死状态
                    enabled = !uiState.loading && (uiState.isLoggedIn || uiState.isConnected),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(30.dp)
                ) {
                    if (uiState.loading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(14.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text(
                            text = if (uiState.isLoggedIn) "退出" else "登录",
                            fontSize = 11.sp,
                            maxLines = 1
                        )
                    }
                }

                OutlinedButton(
                    onClick = { viewModel.onList() },
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(30.dp)
                ) {
                    Text(
                        text = "list",
                        fontSize = 11.sp,
                        maxLines = 1
                    )
                }
            }
        }
    }
}

// MARK: - 紧凑输入框（高度减半，文字上下边距为 0）

@Composable
private fun CompactField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    isPassword: Boolean = false,
    labelOutside: Boolean = false,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default
) {
    if (labelOutside) {
        // 标签在框外左侧（“我”卡片）
        Row(
            modifier = modifier,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = label,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                modifier = Modifier.width(FieldLabelWidth)
            )
            Spacer(modifier = Modifier.width(6.dp))
            CompactFieldBox(
                value = value,
                onValueChange = onValueChange,
                enabled = enabled,
                isPassword = isPassword,
                inlineLabel = null,
                keyboardOptions = keyboardOptions,
                keyboardActions = keyboardActions,
                modifier = Modifier.weight(1f)
            )
        }
    } else {
        // 标签作为灰色前缀放在框内左侧（服务器卡片）
        CompactFieldBox(
            value = value,
            onValueChange = onValueChange,
            enabled = enabled,
            isPassword = isPassword,
            inlineLabel = label,
            keyboardOptions = keyboardOptions,
            keyboardActions = keyboardActions,
            modifier = modifier
        )
    }
}

@Composable
private fun CompactFieldBox(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean,
    isPassword: Boolean,
    inlineLabel: String?,
    keyboardOptions: KeyboardOptions,
    keyboardActions: KeyboardActions,
    modifier: Modifier = Modifier
) {
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        enabled = enabled,
        singleLine = true,
        textStyle = TextStyle(
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurface
        ),
        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
        visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = keyboardOptions,
        keyboardActions = keyboardActions,
        modifier = modifier,
        decorationBox = { innerTextField ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(CompactFieldHeight)
                    .border(
                        width = 1.dp,
                        color = MaterialTheme.colorScheme.outline,
                        shape = RoundedCornerShape(6.dp)
                    )
                    // 上下都不留边距，文字紧贴输入框
                    .padding(horizontal = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (inlineLabel != null) {
                    Text(
                        text = inlineLabel,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Box(modifier = Modifier.weight(1f)) {
                    innerTextField()
                }
            }
        }
    )
}

// MARK: - 自由层：连接线 + “我”卡片 + 其他人节点（拖“名字(ip:port)”那一行可移动）

@Composable
private fun FreeLayer(
    uiState: LoginUiState,
    viewModel: LoginViewModel,
    focusManager: FocusManager,
    showLink: Boolean,
    modifier: Modifier = Modifier
) {
    // 窗口在屏幕上的位置和高度（px），配合 localToWindow() 算屏幕几何中心
    val context = LocalContext.current
    val windowBounds = remember {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.getSystemService(WindowManager::class.java).currentWindowMetrics.bounds
        } else {
            @Suppress("DEPRECATION")
            Rect(
                0, 0,
                context.resources.displayMetrics.widthPixels,
                context.resources.displayMetrics.heightPixels
            )
        }
    }
    var freeLayerTopPx by remember { mutableStateOf(0f) }

    BoxWithConstraints(
        modifier = modifier.onGloballyPositioned { coords ->
            // 记录自由层顶边在窗口里的位置，用来把横线画到屏幕真正的正中心
            freeLayerTopPx = coords.localToWindow(Offset.Zero).y
        }
    ) {
        val areaW: Dp = maxWidth
        val areaH: Dp = maxHeight

        // 每个人的随机位置，存的是 0~1 的相对坐标：
        // 同一次 list 结果 / 同一尺寸下位置保持稳定，不会每帧乱跳
        // y 只取上半段，保证卡片默认落在屏幕上半区域
        val positions = remember(uiState.peers, areaW, areaH) {
            val placed = mutableListOf<Pair<Float, Float>>()
            val minGapX = 0.3f
            val minGapY = 0.2f
            uiState.peers.associate { peer ->
                var candidate = Pair(Random.nextFloat(), Random.nextFloat() * PeerYRange)
                var attempt = 0
                // 简单避让：尽量别让两个卡片叠在一起
                while (attempt < 12 && placed.any {
                        abs(it.first - candidate.first) < minGapX &&
                            abs(it.second - candidate.second) < minGapY
                    }
                ) {
                    candidate = Pair(Random.nextFloat(), Random.nextFloat() * PeerYRange)
                    attempt++
                }
                placed.add(candidate)
                peer.username to candidate
            }
        }

        // ── 拖动状态（px）──
        var meDrag by remember { mutableStateOf(Offset.Zero) }
        val peerDrags = remember { mutableStateMapOf<String, Offset>() }
        val udpSocketDrags = remember { mutableStateMapOf<Long, Offset>() }
        var meCardHeight by remember { mutableStateOf(0f) }
        var meCardWidth by remember { mutableStateOf(0f) }

        // 卡片宽度改成按内容自适应后，连线/拖动边界要用实测宽度
        val peerSizes = remember { mutableStateMapOf<String, IntSize>() }
        val udpSocketSizes = remember { mutableStateMapOf<Long, IntSize>() }

        val density = LocalDensity.current
        val areaWpx = with(density) { areaW.toPx() }
        val areaHpx = with(density) { areaH.toPx() }
        val peerWpx = with(density) { PeerNodeWidth.toPx() }
        val peerHpx = with(density) { PeerNodeHeight.toPx() }
        val udpSocketWpx = with(density) { UdpSocketCardWidth.toPx() }
        val udpSocketHpx = with(density) { UdpSocketCardHeight.toPx() }
        val udpSocketGapPx = with(density) { UdpSocketGap.toPx() }
        val meMarginPx = with(density) { MeCardBottomMargin.toPx() }
        val peerTitleCenterPx = with(density) { PeerTitleCenterY.toPx() }

        /** 实测不到的宽度先用常量估算 */
        fun peerWidthPx(name: String): Float = peerSizes[name]?.width?.toFloat() ?: peerWpx
        fun udpSocketWidthPx(id: Long): Float = udpSocketSizes[id]?.width?.toFloat() ?: udpSocketWpx
        fun udpSocketHeightPx(id: Long): Float = udpSocketSizes[id]?.height?.toFloat() ?: udpSocketHpx

        /** 其他人节点没被拖动时的随机位置 */
        fun peerBase(name: String): Offset {
            val rel = positions[name] ?: return Offset.Zero
            val maxX = (areaWpx - peerWidthPx(name)).coerceAtLeast(0f)
            val maxY = (areaHpx - peerHpx).coerceAtLeast(0f)
            return Offset(maxX * rel.first, maxY * rel.second)
        }

        /** 其他人节点当前左上角（随机位置 + 拖动位移） */
        fun peerTopLeft(name: String): Offset = peerBase(name) + (peerDrags[name] ?: Offset.Zero)

        /**
         * UDP socket 卡片的基准位置：**只在卡片刚出现时算一次**（此时挂在对方卡片正下方、下半屏），
         * 之后固定不动 —— 对方卡片再被拖动也不会带着它走。
         * 用普通 Map 缓存（值不会再变，无需触发重组）。
         */
        val frozenSocketBases = remember { mutableMapOf<Long, Offset>() }

        fun udpSocketBase(card: UdpSessionInfo): Offset {
            frozenSocketBases[card.id]?.let { return it }
            val size = udpSocketSizes[card.id]
            if (size == null) {
                // 尺寸还没量到：先给个临时位置（下半屏居中），不冻结
                return Offset(
                    ((areaWpx - udpSocketWpx) / 2f).coerceAtLeast(0f),
                    (areaHpx / 2f).coerceAtLeast(0f)
                )
            }
            val sockW = size.width.toFloat()
            val sockH = size.height.toFloat()
            val maxX = (areaWpx - sockW).coerceAtLeast(0f)
            val maxY = (areaHpx - sockH).coerceAtLeast(0f)
            val peerTop = positions[card.target]?.let { peerTopLeft(card.target) }
            val baseX = if (peerTop != null) peerTop.x + (peerWidthPx(card.target) - sockW) / 2f
            else (areaWpx - sockW) / 2f
            val baseY = if (peerTop != null) maxOf(areaHpx / 2f, peerTop.y + peerHpx + udpSocketGapPx)
            else areaHpx / 2f
            val base = Offset(baseX.coerceIn(0f, maxX), baseY.coerceIn(0f, maxY))
            frozenSocketBases[card.id] = base
            return base
        }

        /** UDP socket 卡片当前左上角 = 冻结的基准位置 + 它自己的拖动位移 */
        fun udpSocketTopLeft(card: UdpSessionInfo): Offset =
            udpSocketBase(card) + (udpSocketDrags[card.id] ?: Offset.Zero)

        /** “我”卡片默认贴底居中，这里算它拖动后中心点（给连线用） */
        fun meCenter(): Offset = Offset(
            areaWpx / 2f + meDrag.x,
            areaHpx - meMarginPx - meCardHeight / 2f + meDrag.y
        )

        val branchColor = LinkGreen   // 其他人的连线：绿色实线
        // 中间横向分界线的颜色（上面 = 服务器 / 别人的机器，下面 = 自己的端口和工具）
        val dividerColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.35f)

        Canvas(modifier = Modifier.fillMaxSize()) {
            val strokePx = LinkStrokeWidth.toPx()
            val dash = PathEffect.dashPathEffect(
                floatArrayOf(LinkDashOn.toPx(), LinkDashOff.toPx()),
                0f
            )
            val topY = 0f   // 服务器卡片底边 = 自由层顶边

            // 屏幕正中间的横向分界线，从左到右贯通
            // y 用「窗口顶 + 窗口高一半」换算到自由层坐标系，保证落在屏幕几何中心
            val dividerY = windowBounds.top + windowBounds.height() / 2f - freeLayerTopPx
            // freeLayerTopPx 还没量到时先不画，避免第一帧出现在错误位置
            if (freeLayerTopPx > 0f && dividerY in 0f..size.height) {
                drawLine(
                    color = dividerColor,
                    start = Offset(0f, dividerY),
                    end = Offset(size.width, dividerY),
                    strokeWidth = 1.dp.toPx()
                )
            }

            // 服务器 ↔ 我：起点 x = “我”卡片中心 x，垂直线
            // 已连接未登录 → 白色虚线；登录后 → 绿色实线（不加粗）
            if (showLink && meCardHeight > 0f) {
                val center = meCenter()
                drawLine(
                    color = if (uiState.isLoggedIn) LinkGreen else Color.White,
                    start = Offset(center.x, topY),
                    end = center,
                    strokeWidth = strokePx,
                    cap = StrokeCap.Round,
                    pathEffect = if (uiState.isLoggedIn) null else dash
                )
            }

            // 服务器 ↔ 其他每个人：起点 x = 该卡片中心 x，绿色实线
            uiState.peers.forEach { peer ->
                val topLeft = peerTopLeft(peer.username)
                val centerX = topLeft.x + peerWidthPx(peer.username) / 2f
                drawLine(
                    color = branchColor,
                    start = Offset(centerX, topY),
                    end = Offset(centerX, topLeft.y + peerTitleCenterPx),
                    strokeWidth = strokePx,
                    cap = StrokeCap.Round
                )
            }

            // 其他人卡片 ↔ 它的 UDP socket 卡片：白色虚线
            uiState.udpSockets.forEach { card ->
                val peerTop = positions[card.target]?.let { peerTopLeft(card.target) } ?: return@forEach
                val sockTop = udpSocketTopLeft(card)
                drawLine(
                    color = Color.White,
                    start = Offset(peerTop.x + peerWidthPx(card.target) / 2f, peerTop.y + peerHpx),
                    end = Offset(sockTop.x + udpSocketWidthPx(card.id) / 2f, sockTop.y),
                    strokeWidth = strokePx,
                    cap = StrokeCap.Round,
                    pathEffect = dash
                )
            }
        }

        // ── “我”卡片：默认贴底居中（x 占 25%~75%），拖标题行可移动 ──
        MeCard(
            uiState = uiState,
            viewModel = viewModel,
            focusManager = focusManager,
            onDrag = { delta ->
                val maxDx = ((areaWpx - meCardWidth) / 2f).coerceAtLeast(0f)
                // 纵向上下限：上到自由层顶部（贴住服务器卡片下沿），下到贴底
                val hiY = meMarginPx
                val loY = (-(areaHpx - meCardHeight - meMarginPx)).coerceAtMost(hiY)
                meDrag = Offset(
                    (meDrag.x + delta.x).coerceIn(-maxDx, maxDx),
                    (meDrag.y + delta.y).coerceIn(loY, hiY)
                )
            },
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = MeCardBottomMargin)
                .offset { IntOffset(meDrag.x.roundToInt(), meDrag.y.roundToInt()) }
                .onSizeChanged {
                    meCardHeight = it.height.toFloat()
                    meCardWidth = it.width.toFloat()
                }
        )

        // ── 其他人节点：随机摆放，拖标题行可移动 ──
        uiState.peers.forEach { peer ->
            PeerNode(
                peer = peer,
                viewModel = viewModel,
                onDrag = { delta ->
                    val base = peerBase(peer.username)
                    val maxX = (areaWpx - peerWidthPx(peer.username)).coerceAtLeast(0f)
                    val maxY = (areaHpx - peerHpx).coerceAtLeast(0f)
                    val cur = peerDrags[peer.username] ?: Offset.Zero
                    peerDrags[peer.username] = Offset(
                        (cur.x + delta.x).coerceIn(-base.x, maxX - base.x),
                        (cur.y + delta.y).coerceIn(-base.y, maxY - base.y)
                    )
                },
                modifier = Modifier
                    .offset {
                        val topLeft = peerTopLeft(peer.username)
                        IntOffset(topLeft.x.roundToInt(), topLeft.y.roundToInt())
                    }
                    .height(PeerNodeHeight)
                    .onSizeChanged { peerSizes[peer.username] = it }
            )
        }

        // ── UDP socket 卡片：socket 创建时出现，挂在对应 peer 卡片下方，可拖动，右上角 ✕ 关闭 ──
        // 放在最后绘制，保证压在其他卡片之上、✕ 始终可点
        // 位置只在创建时按对方卡片算一次，之后不再跟随对方移动
        uiState.udpSockets.forEach { card ->
            UdpSocketCardView(
                card = card,
                onClose = {
                    // 关掉时顺手清掉这张卡片的位置缓存
                    udpSocketDrags.remove(card.id)
                    frozenSocketBases.remove(card.id)
                    viewModel.closeUdpSocket(card.id)
                },
                onDrag = { delta ->
                    val base = udpSocketBase(card)
                    val maxX = (areaWpx - udpSocketWidthPx(card.id)).coerceAtLeast(0f)
                    val maxY = (areaHpx - udpSocketHeightPx(card.id)).coerceAtLeast(0f)
                    val cur = udpSocketDrags[card.id] ?: Offset.Zero
                    udpSocketDrags[card.id] = Offset(
                        (cur.x + delta.x).coerceIn(-base.x, maxX - base.x),
                        (cur.y + delta.y).coerceIn(-base.y, maxY - base.y)
                    )
                },
                onUse = { usageId -> viewModel.useUdpSocket(card.id, usageId) },
                modifier = Modifier
                    .offset {
                        val topLeft = udpSocketTopLeft(card)
                        IntOffset(topLeft.x.roundToInt(), topLeft.y.roundToInt())
                    }
                    .onSizeChanged { udpSocketSizes[card.id] = it }
            )
        }
    }
}

/** socket 卡片：UDP 显示本机绑定 + 五步进度；direct 显示三步探测 + 可达地址；tcp / upnp 只显示流程。整卡可拖动，右上角 ✕ 关闭 */
@Composable
private fun UdpSocketCardView(
    card: UdpSessionInfo,
    onClose: () -> Unit,
    onDrag: (Offset) -> Unit,
    onUse: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    // 三种卡片：只画计划（tcp / upnp）／真有 socket（udp）／没有 socket 的真实流程（direct）
    val isPreview = card.isPreview
    val hasSocket = card.kind == "udp"
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .dragHandle(onDrag),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(
            // 宽高都按内容自适应（宽度 = 内部最宽那一行）
            modifier = Modifier.width(IntrinsicSize.Max)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = when {
                        isPreview -> "${card.kind} 流程预览"
                        hasSocket -> "UDP socket"
                        else -> "${card.kind} 直连探测 · ${card.target}"
                    },
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 8.dp)
                )
                Box(
                    modifier = Modifier
                        .clickable { onClose() }
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "✕",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (isPreview) {
                // tcp / upnp：只显示计划步骤（真实逻辑还没实现，所以全是 ○）
                card.plan.forEach { step ->
                    UdpStepRow(step.text, step.done)
                    if (step.detail.isNotEmpty()) UdpInfoRow(step.detail)
                }
                Text(
                    text = "（仅流程预览，尚未实现真实握手）",
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    modifier = Modifier.padding(start = 8.dp, end = 8.dp, top = 2.dp, bottom = 4.dp)
                )
            } else if (!hasSocket) {
                // direct：没有 socket，三步进度是实时打勾的，末行是结果
                card.plan.forEach { step ->
                    UdpStepRow(step.text, step.done)
                    if (step.detail.isNotEmpty()) UdpInfoRow(step.detail)
                }
                if (card.note.isNotEmpty()) {
                    Text(
                        text = card.note,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = if (card.note.startsWith("可达")) LinkGreen
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .widthIn(max = DirectNoteMaxWidth)
                            .padding(start = 22.dp, end = 8.dp, top = 2.dp)
                    )
                }
                Text(
                    text = "（direct 只证明地址可达，不建隧道）",
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    modifier = Modifier.padding(start = 8.dp, end = 8.dp, top = 2.dp, bottom = 4.dp)
                )
            } else {
                Text(
                    text = "本机绑定 ${formatHostPort(card.localIp, card.localPort)}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .padding(start = 8.dp, end = 8.dp, bottom = 2.dp)
                )

                // 打洞四步，每完成一步打勾
                UdpStepRow("发给服务器", card.sentToServer)
                UdpStepRow("收到服务器回复", card.serverReplied)
                if (card.serverReplied) {
                    UdpInfoRow("公网 ${formatHostPort(card.myPublicIp, card.myPublicPort)}")
                    UdpInfoRow("对方 ${formatHostPort(card.peerPublicIp, card.peerPublicPort)}")
                }
                UdpStepRow("发给对端", card.sentToPeer)
                UdpStepRow("收到对端回复", card.peerReplied)

                // 第 5 行：选用法。第 4 步（收到对端回复）打勾之后才可点
                Row(
                    modifier = Modifier.padding(start = 8.dp, end = 8.dp, bottom = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    UsageButton("udptest", card.peerReplied, card.handedTo == "udptest") { onUse("udptest") }
                    UsageButton("tun", card.peerReplied, card.handedTo == "tun") { onUse("tun") }
                    UsageButton("switch", card.peerReplied, card.handedTo == "switch") { onUse("switch") }
                    UsageButton("wg", card.peerReplied, card.handedTo == "wg") { onUse("wg") }
                }
            }
        }
    }
}

/** socket 卡片第 5 行的用法按钮 */
@Composable
private fun RowScope.UsageButton(
    text: String,
    enabled: Boolean,
    selected: Boolean,
    onClick: () -> Unit
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(6.dp),
        contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp),
        border = BorderStroke(
            width = 1.dp,
            color = when {
                selected -> LinkGreen
                enabled -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
            }
        ),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = if (selected) LinkGreen else MaterialTheme.colorScheme.primary,
            disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
        ),
        modifier = Modifier.height(24.dp)
    ) {
        Text(text = text, fontSize = 10.sp, maxLines = 1)
    }
}

/** socket 卡片里的一步：完成打 ✓，未完成是 ○ */
@Composable
private fun UdpStepRow(label: String, done: Boolean) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(start = 8.dp, end = 8.dp)
    ) {
        Text(
            text = if (done) "✓" else "○",
            fontSize = 11.sp,
            color = if (done) LinkGreen else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = label,
            fontSize = 11.sp,
            color = if (done) MaterialTheme.colorScheme.onSurface
            else MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

/** 服务器回复里带的地址信息（缩进一级） */
@Composable
private fun UdpInfoRow(text: String) {
    Text(
        text = text,
        fontSize = 10.sp,
        fontFamily = FontFamily.Monospace,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier.padding(start = 22.dp, end = 8.dp)
    )
}

/** 一个其他人的节点：和“我”卡片同一种外框，里面是 名字(ip:port) + 那一排按钮 */
@Composable
private fun PeerNode(
    peer: PeerEntry,
    viewModel: LoginViewModel,
    onDrag: (Offset) -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.clip(RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            // 高度固定，宽度 = 内部最宽那一行（自适应）
            modifier = Modifier
                .fillMaxHeight()
                .width(IntrinsicSize.Max),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // 拖动把手：名字(ip:port) 这一行
            Text(
                text = nodeLabel(peer.username, peer.ip, peer.port),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .dragHandle(onDrag)
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(PeerActionHeight),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // 这里只有「打洞」行为（direct / upnp / udp / tcp）；
                // 任何「应用」行为（udptest / tun / switch / wg / 聊天…）都在打洞成功后
                // 出现在 socket 卡片第 5 行上选，不放在这里。
                PeerAction("direct") { viewModel.onDirect(peer.username) }
                PeerAction("upnp") { viewModel.onUpnp(peer.username) }
                PeerAction("udp") { viewModel.onUdp(peer.username) }
                PeerAction("tcp") { viewModel.onTcp(peer.username) }
            }
        }
    }
}

/** 其他人节点下面那排按钮的宽度（比均分窄） */
private val PeerActionWidth = 44.dp

@Composable
private fun RowScope.PeerAction(text: String, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        shape = RoundedCornerShape(6.dp),
        contentPadding = PaddingValues(horizontal = 0.dp, vertical = 0.dp),
        modifier = Modifier
            .width(PeerActionWidth)
            .fillMaxHeight()
    ) {
        Text(
            text = text,
            fontSize = 10.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

/** 拖动把手：只让挂了这个 modifier 的那一行能拖动卡片 */
@Composable
private fun Modifier.dragHandle(onDrag: (Offset) -> Unit): Modifier {
    val current by rememberUpdatedState(onDrag)
    return this.pointerInput(Unit) {
        detectDragGestures { change, dragAmount ->
            change.consume()
            current(dragAmount)
        }
    }
}

// MARK: - App 内日志面板

@Composable
private fun AppLogPanel(
    messages: List<MessageItem>,
    onClear: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // 新日志到达时自动滚到底部
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    LaunchedEffect(copied) {
        if (copied) {
            delay(1500)
            copied = false
        }
    }

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        shadowElevation = 16.dp
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "App 内日志",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (messages.isNotEmpty()) {
                        TextButton(
                            onClick = onClear,
                            modifier = Modifier.height(28.dp),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                        ) {
                            Text("清空", fontSize = 10.sp)
                        }
                    }
                    TextButton(
                        onClick = {
                            val text = messages.joinToString("\n") { "${it.direction.name}: ${it.content}" }
                            clipboardManager.setText(AnnotatedString(text))
                            copied = true
                        },
                        enabled = messages.isNotEmpty(),
                        modifier = Modifier.height(28.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                    ) {
                        Text("📋复制", fontSize = 10.sp)
                    }
                    if (copied) {
                        Text(
                            text = "已复制",
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(start = 4.dp)
                        )
                    }
                    TextButton(
                        onClick = onClose,
                        modifier = Modifier.height(28.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                    ) {
                        Text("✕", fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(6.dp))

            if (messages.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = "暂无日志",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        // 底部留白，避免日志被右下角“日志”按钮挡住
                        contentPadding = PaddingValues(bottom = 56.dp),
                        modifier = Modifier.fillMaxSize()
                    ) {
                        itemsIndexed(messages, key = { index, _ -> index }) { _, item ->
                            AppLogRow(item)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppLogRow(item: MessageItem) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Start
    ) {
        Text(
            text = when (item.direction) {
                Direction.CLIENT -> "client:"
                Direction.SERVER -> "server:"
                Direction.SYSTEM -> "android:"
                Direction.UDP_SEND -> "→ "
                Direction.UDP_RECV -> "← "
            },
            fontSize = 10.sp,
            lineHeight = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = when (item.direction) {
                Direction.CLIENT -> MaterialTheme.colorScheme.primary
                Direction.SERVER -> MaterialTheme.colorScheme.tertiary
                Direction.SYSTEM -> MaterialTheme.colorScheme.error
                Direction.UDP_SEND -> MaterialTheme.colorScheme.primary
                Direction.UDP_RECV -> MaterialTheme.colorScheme.tertiary
            },
            modifier = Modifier.width(52.dp)
        )
        Text(
            text = item.content,
            fontSize = 10.sp,
            lineHeight = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
