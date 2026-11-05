package io.github.junweiup.commonrelay.kotlin

import io.github.junweiup.commonrelay.Crypto
import io.github.junweiup.commonrelay.RelayClient
import io.github.junweiup.commonrelay.RelayFiles
import okhttp3.OkHttpClient
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

/**
 * Connects with the server access password sent as `Relay-Access` (8-128 printable ASCII).
 * Pass null only for relays that do not require one. The password is not an end-to-end key.
 */
fun RelayClient.connectRelay(url: String, token: String, password: String? = null, allowLocalTest: Boolean = false) =
    connect(url, token, password, allowLocalTest)

/** Blocking file API (call from Dispatchers.IO); every request carries `Relay-Access` when password is set. */
fun relayFiles(http: OkHttpClient, base: String, token: String, password: String? = null): RelayFiles =
    RelayFiles(http, base, token, password)

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
