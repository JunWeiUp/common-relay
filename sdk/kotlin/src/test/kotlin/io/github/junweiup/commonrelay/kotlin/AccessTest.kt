package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.RelayAccess
import io.github.junweiup.commonrelay.RelayClient
import okhttp3.*
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class AccessTest {
    private val password = "{{SECRET_wqohqbku}}"
    private fun recording(seen: MutableList<Request>) = OkHttpClient.Builder().addInterceptor { chain ->
        val r = chain.request(); seen.add(r)
        Response.Builder().request(r).protocol(Protocol.HTTP_1_1).code(401).message("Unauthorized").body("unauthorized".toResponseBody()).build()
    }.build()

    @Test fun wrappersSendAccessPassword() {
        val seen = CopyOnWriteArrayList<Request>()
        val closed = CountDownLatch(1)
        val identity = relayIdentity("example", "test", "alice", "01".repeat(32), emptyMap())
        RelayClient(recording(seen), identity, object : RelayClient.Listener {
            override fun onReady() {}
            override fun onEvent(event: JSONObject) {}
            override fun onClosed(error: Throwable) { closed.countDown() }
        }).use { client ->
            assertThrows(IllegalArgumentException::class.java) { client.connectRelay("wss://relay.example.com/relay/v1/ws", "0".repeat(64), "short") }
            client.connectRelay("wss://relay.example.com/relay/v1/ws", "0".repeat(64), password)
            assertTrue(closed.await(5, TimeUnit.SECONDS))
        }
        val files = relayFiles(recording(seen), "https://relay.example.com/relay/v1/files", "0".repeat(64), password)
        assertThrows(Exception::class.java) { files.inbox() }
        assertEquals(2, seen.size)
        seen.forEach { assertEquals(password, it.header(RelayAccess.HEADER)) }
    }
}
