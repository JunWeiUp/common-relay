package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.Crypto
import io.github.junweiup.commonrelay.RelayClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runInterruptible
import org.json.JSONObject

/** Pin trustedPeers through a trusted pairing channel; discovery is not trust. */
fun relayIdentity(
    app: String,
    group: String,
    device: String,
    secretKey: String,
    trustedPeers: Map<String, String>,
): Crypto = Crypto(app, group, device, secretKey, trustedPeers)

/** Cancellation removes the pending wait; it cannot undo a frame already sent. */
suspend fun RelayClient.onlinePeers(): JSONObject = peers().await()

/** Offline delivery requires RelayJournal; persist/reuse id for an explicit retry. */
suspend fun RelayClient.sendMessage(
    to: String,
    data: ByteArray,
    offline: Boolean = false,
    id: String? = null,
): JSONObject = message(to, data, offline, id).await()

suspend fun RelayClient.acknowledgeMessage(event: JSONObject): JSONObject = acknowledge(event).await()

// Keep ownership explicit: these return the Java future, so a cancelled waiter
// cannot silently lose an accepted stream. Use the shared Java stream lifecycle.
fun RelayClient.openByteStream(peer: String) = openStream(peer)
fun RelayClient.acceptByteStream(event: JSONObject) = acceptStream(event)

/** Blocking stream reads/writes run on IO and close the stream on cancellation. */
suspend fun RelayClient.Stream.readChunk(): ByteArray = try {
    runInterruptible(Dispatchers.IO) { receive() }
} catch (error: Exception) { close(); throw error }

suspend fun RelayClient.Stream.writeChunk(data: ByteArray, final: Boolean = false) {
    try { runInterruptible(Dispatchers.IO) { send(data, final) } }
    catch (error: Exception) { close(); throw error }
}
