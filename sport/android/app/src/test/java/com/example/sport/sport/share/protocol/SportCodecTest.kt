package com.example.sport.sport.share.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 报文往返测试。纯 JVM，不碰 Android。
 *
 * 这里盯的是「编出去 → 解回来」必须一模一样，以及脏数据不能让对端崩。
 */
class SportCodecTest {

    private fun roundTrip(event: SportEvent): SportEvent {
        val line = SportCodec.encode(event)
        val decoded = SportCodec.decode(line)
        assertTrue("解不出来：$line", decoded != null)
        return decoded!!
    }

    /** 拿起：球员。 */
    @Test
    fun dragStartedWithPlayerRoundTrips() {
        val event = DragStarted(
            sport = SportKind.FOOTBALL,
            seq = 7L,
            ref = PlayerRef.away(9),
            from = Coord.ofMeters(-9.5f, 0f),
        )
        val back = roundTrip(event) as DragStarted

        assertEquals(SportKind.FOOTBALL, back.sport)
        assertEquals(7L, back.seq)
        assertEquals(1, back.ref.side)
        assertEquals(9, back.ref.number)
        assertEquals(-9500, back.from.x)
        assertEquals(0, back.from.y)
    }

    /** 拿起：球（side 哨兵 = -1）。 */
    @Test
    fun dragStartedWithBallRoundTrips() {
        val event = DragStarted(SportKind.BASKETBALL, 3L, PlayerRef.BALL_REF, Coord.ofMeters(1.5f, -2.25f))
        val back = roundTrip(event) as DragStarted

        assertTrue(back.ref.isBall)
        assertEquals(1500, back.from.x)
        assertEquals(-2250, back.from.y)
    }

    /** 拖动中的位置。 */
    @Test
    fun dragMovedRoundTrips() {
        val event = DragMoved(SportKind.FOOTBALL, 8L, PlayerRef.home(4), Coord.ofMeters(12.345f, -6.789f))
        val back = roundTrip(event) as DragMoved

        assertEquals(0, back.ref.side)
        assertEquals(4, back.ref.number)
        // 毫米精度：1 毫米以内
        assertEquals(12.345f, back.pos.metersX, 0.001f)
        assertEquals(-6.789f, back.pos.metersY, 0.001f)
    }

    /** 松手：committed 两种取值都要能还原。 */
    @Test
    fun dragEndedRoundTripsBothCommitFlags() {
        for (committed in listOf(true, false)) {
            val event = DragEnded(
                SportKind.BASKETBALL,
                9L,
                PlayerRef.home(1),
                Coord.ofMeters(0f, 0f),
                committed,
            )
            val back = roundTrip(event) as DragEnded
            assertEquals(committed, back.committed)
        }
    }

    /** 全量状态：所有人 + 球，一个都不能丢。 */
    @Test
    fun stateChangedRoundTripsEveryPlayer() {
        val players = mapOf(
            PlayerRef.home(1) to Coord.ofMeters(-50f, 0f),
            PlayerRef.home(9) to Coord.ofMeters(-9.5f, 0f),
            PlayerRef.away(1) to Coord.ofMeters(50f, 0f),
            PlayerRef.away(11) to Coord.ofMeters(9.5f, -21f),
        )
        val event = StateChanged(
            SportKind.FOOTBALL,
            11L,
            CourtState(players, Coord.ofMeters(0f, 0f)),
        )
        val back = roundTrip(event) as StateChanged

        assertEquals(players.size, back.state.players.size)
        for ((ref, pos) in players) {
            val got = back.state.players[ref]
            assertTrue("少了 $ref", got != null)
            assertEquals(pos.x, got!!.x)
            assertEquals(pos.y, got.y)
        }
        assertEquals(0, back.state.ball.x)
    }

    /** 空状态（比如排球还没做）也要能往返，不能崩。 */
    @Test
    fun stateChangedWithNoPlayersRoundTrips() {
        val event = StateChanged(SportKind.VOLLEYBALL, 1L, CourtState(emptyMap(), Coord.ORIGIN))
        val back = roundTrip(event) as StateChanged
        assertTrue(back.state.players.isEmpty())
    }

    /** 重置。 */
    @Test
    fun boardResetRoundTrips() {
        val back = roundTrip(BoardReset(SportKind.FOOTBALL, 20L)) as BoardReset
        assertEquals(SportKind.FOOTBALL, back.sport)
        assertEquals(20L, back.seq)
    }

    /** 报文形状：一行为一条，值里不能出现 `|`。 */
    @Test
    fun encodedLineHasNoStraySeparators() {
        val line = SportCodec.encode(
            StateChanged(
                SportKind.FOOTBALL,
                5L,
                CourtState(mapOf(PlayerRef.home(1) to Coord.ofMeters(-50f, 0f)), Coord.ORIGIN),
            ),
        )
        assertTrue(line.startsWith("v1|sport=football|seq=5|t=state|"))
        // 解出来的字段数和重新编码后一致（也就是没有多余分隔符把字段切坏）
        assertEquals(line, SportCodec.encode(SportCodec.decode(line)!!))
    }

    /** 脏数据一律返回 null，不抛异常。 */
    @Test
    fun garbageIsRejected() {
        assertNull(SportCodec.decode(""))
        assertNull(SportCodec.decode("随便一句话"))
        assertNull(SportCodec.decode("v2|sport=football|seq=1|t=reset"))          // 版本不对
        assertNull(SportCodec.decode("v1|sport=unknown|seq=1|t=reset"))           // 球种不认识
        assertNull(SportCodec.decode("v1|sport=football|t=reset"))                // 缺 seq
        assertNull(SportCodec.decode("v1|sport=football|seq=1|t=whatever"))       // 类型不认识
        assertNull(SportCodec.decode("v1|sport=football|seq=abc|t=reset"))        // seq 不是数字
    }

    /** 坐标字段缺失时退化成 0，而不是整条丢弃（拖动流丢一帧无所谓）。 */
    @Test
    fun missingCoordinateFallsBackToOrigin() {
        val back = SportCodec.decode("v1|sport=football|seq=1|t=drag_move|side=0|num=7") as DragMoved
        assertEquals(0, back.pos.x)
        assertEquals(0, back.pos.y)
    }

    /** 球员列表里的坏条目跳过，好条目保留。 */
    @Test
    fun brokenPlayerEntriesAreSkipped() {
        val line = "v1|sport=football|seq=1|t=state|ball=1,2|p=0:9:100:200;坏;1:3:x:y;1:5:300:400"
        val back = SportCodec.decode(line) as StateChanged

        assertEquals(2, back.state.players.size)
        assertEquals(100, back.state.players[PlayerRef.home(9)]!!.x)
        assertEquals(400, back.state.players[PlayerRef.away(5)]!!.y)
        assertEquals(1, back.state.ball.x)
        assertEquals(2, back.state.ball.y)
    }
}
