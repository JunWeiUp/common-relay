package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.RelayClient
import io.github.junweiup.commonrelay.RelayJournal
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.future.await
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.TimeUnit

class KotlinInteropTest {
    @Test fun localEcho() = runBlocking {
        val path = System.getenv("COMMON_RELAY_QA_CONFIG")
        assumeTrue(path != null)
        val c = JSONObject(File(path!!).readText())
        require(c.optBoolean("allow_local_test")) { "Local tests only" }
        val trusted = c.getJSONObject("trusted_peers")
        val identity = relayIdentity(c.getString("app"), c.getString("group"), c.getString("device"),
            c.getString("secret_key"), trusted.keys().asSequence().associateWith { trusted.getString(it) })
        val events = Channel<JSONObject>(64)
        val ready = CompletableDeferred<Unit>()
        val http = OkHttpClient.Builder().pingInterval(20, TimeUnit.SECONDS).build()
        val client = RelayClient(http, identity, object : RelayClient.Listener {
            override fun onReady() { ready.complete(Unit) }
            override fun onEvent(event: JSONObject) { check(events.trySend(event).isSuccess) }
            override fun onClosed(error: Throwable) { ready.completeExceptionally(error); events.close(error) }
        }, RelayJournal(Path.of(c.getString("state_path"))))
        try {
            client.connect(c.getString("url"), c.getString("token"), true)
            withTimeout(120_000) {
                ready.await()
                check(client.onlinePeers().getJSONArray("devices").length() > 0)
                while (true) {
                    val event = events.receive()
                    when (event.getString("type")) {
                        "message" -> {
                            client.sendMessage(event.getString("from"), Base64.getDecoder().decode(event.getString("data")), offline = event.optBoolean("offline"))
                            if (event.optBoolean("offline")) client.acknowledgeMessage(event)
                        }
                        "stream.open" -> {
                            val stream = client.acceptByteStream(event).await()
                            try {
                                while (!stream.receivedFinal()) {
                                    val bytes = stream.readChunk()
                                    stream.writeChunk(bytes, final = stream.receivedFinal())
                                }
                                delay(1500)
                            } finally { stream.close() }
                            break
                        }
                    }
                }
            }
        } finally {
            client.close(); http.dispatcher.executorService.shutdownNow(); http.connectionPool.evictAll()
        }
    }
}
