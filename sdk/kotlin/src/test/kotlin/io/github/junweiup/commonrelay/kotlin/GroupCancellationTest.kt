package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.RelayGroups
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class GroupCancellationTest {
    @Test fun cancellingCoroutineCancelsGroupRequest() = runBlocking {
        val started = CountDownLatch(1)
        val held = CopyOnWriteArrayList<Socket>()
        ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).use { server ->
            Thread { runCatching { while (true) { held.add(server.accept()); started.countDown() } } }.apply { isDaemon = true }.start()
            val groups = RelayGroups(JSONObject().put("url", "ws://127.0.0.1:${server.localPort}/relay/v1/ws").put("app", "test").put("device", "test"), true)
            val request = async(Dispatchers.Default) { groups.groupCall { call("GET", "/group", null, null) } }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            withTimeout(2_000) {
                request.cancel()
                try { request.await(); fail("request survived cancellation") } catch (_: CancellationException) {}
            }
            held.forEach { it.close() }
        }
    }
}
