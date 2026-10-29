package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.RelayGroups
import kotlinx.coroutines.*
import kotlinx.coroutines.future.await
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.concurrent.CompletableFuture

class RelayTest {
    @Test fun sharedVectorsAndTrustBoundary() {
        val v = JSONObject(File("../../protocol/crypto-vectors.json").readText())
        val bob = relayIdentity(v.getString("app"), v.getString("group"), "bob",
            v.getString("bob_secret"), mapOf("alice" to v.getString("alice_public")))
        assertEquals(v.getString("bob_public"), bob.publicKey())
        assertEquals("aGVsbG8=", bob.open("alice", "message", v.getString("id"), v.getString("message")).getString("data"))
        assertThrows(Exception::class.java) { bob.open("alice", "message", "wrong", v.getString("message")) }
        val g = JSONObject(File("../../protocol/group-vectors.json").readText())
        val groups = RelayGroups(g.getJSONObject("config"), false)
        groups.advance(g.getJSONObject("initial"), g.getJSONObject("auto_admission").getJSONObject("approved"))
        val invalid = g.getJSONObject("strict_payload").getJSONArray("invalid")
        for (i in 0 until invalid.length()) assertThrows(Exception::class.java) {
            groups.advance(g.getJSONObject("approved"), invalid.getJSONObject(i).getJSONObject("entry"))
        }
    }

    @Test fun cancellationCancelsPendingFuture() = runBlocking {
        val future = CompletableFuture<JSONObject>()
        val job = launch(start = CoroutineStart.UNDISPATCHED) { future.await() }
        job.cancelAndJoin()
        assertTrue(future.isCancelled)
    }
}
