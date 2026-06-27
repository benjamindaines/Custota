/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Client for `benbackupd`, the small init-launched helper that holds
 * CAP_DAC_READ_SEARCH and an SELinux domain permitted to read app_data_file
 * (and friends). It replaces Neo-Backup's root-shell file access:
 *
 *   Neo-Backup (root)                 ->  here (no root)
 *   ShellHandler.suGetDetailed...     ->  PrivilegedFs.list()
 *   quirkLibsuReadFileWorkaround      ->  PrivilegedFs.readFile()
 *
 * The updater app itself never touches app_data_file; only the daemon does.
 * The app only needs to connect to the daemon's unix socket (granted to
 * custota_app via the custota-selinux patch).
 *
 * Wire protocol (SOCK_SEQPACKET, little-endian), see benbackupd.cpp:
 *   Request  : u8 op ('L' list | 'R' read), u16 pathLen, path bytes
 *   'L' reply: stream of records, each:
 *                u8 type (1 reg, 2 dir, 3 symlink, 4 fifo, 0xFE error, 0xFF end)
 *                u32 mode (st_mode & 07777)
 *                u32 uid, u32 gid
 *                u64 size
 *                i64 mtimeSec, u32 mtimeNsec
 *                u16 relLen, rel bytes      (path relative to the listed root)
 *                u16 linkLen, link bytes    (symlink target, else empty)
 *   'R' reply: u8 status (0 ok, 1 error), then if ok: u64 size, then size bytes
 *              (streamed across multiple seqpacket messages)
 */
package com.chiller3.custota.backup

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.DataInputStream
import java.io.EOFException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PrivilegedFs(
    private val socketName: String = SOCKET_NAME,
) {
    enum class NodeType(val wire: Int) {
        REGULAR(1), DIRECTORY(2), SYMLINK(3), FIFO(4);
        companion object {
            fun of(w: Int) = entries.firstOrNull { it.wire == w }
        }
    }

    data class Node(
        val type: NodeType,
        val mode: Int,          // permission bits only (st_mode & 07777)
        val uid: Int,
        val gid: Int,
        val size: Long,
        val mtimeSec: Long,
        val mtimeNsec: Int,
        val relPath: String,    // relative to the listed root, no leading "./"
        val linkTarget: String, // for symlinks; empty otherwise
    )

    private fun connect(): LocalSocket {
        val s = LocalSocket(LocalSocket.SOCKET_STREAM)
        s.connect(LocalSocketAddress(socketName, LocalSocketAddress.Namespace.RESERVED))
        return s
    }

    private fun request(op: Char, path: String): ByteArray {
        val pb = path.toByteArray(Charsets.UTF_8)
        require(pb.size <= 0xFFFF) { "path too long" }
        return ByteBuffer.allocate(1 + 2 + pb.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            put(op.code.toByte())
            putShort(pb.size.toShort())
            put(pb)
        }.array()
    }

    /** Recursive listing of [absPath]'s contents (children only, like Neo-Backup). */
    fun list(absPath: String): List<Node> {
        connect().use { sock ->
            sock.outputStream.write(request('L', absPath))
            sock.outputStream.flush()
            val input = DataInputStream(sock.inputStream.buffered())
            val out = ArrayList<Node>()
            while (true) {
                val type = input.read()
                if (type < 0) break
                if (type == 0xFF) break          // end
                if (type == 0xFE) {              // daemon-side error for a node; skip
                    skipErrorRecord(input)
                    continue
                }
                val nt = NodeType.of(type) ?: continue
                val mode = readU32(input)
                val uid = readU32(input)
                val gid = readU32(input)
                val size = readU64(input)
                val mSec = readI64(input)
                val mNsec = readU32(input)
                val rel = readLenString(input)
                val link = readLenString(input)
                out.add(Node(nt, mode, uid, gid, size, mSec, mNsec, rel, link))
            }
            return out
        }
    }

    /** Stream the bytes of [absPath] into [sink]. Returns bytes copied. */
    fun readFile(absPath: String, sink: OutputStream): Long {
        connect().use { sock ->
            sock.outputStream.write(request('R', absPath))
            sock.outputStream.flush()
            val input = DataInputStream(sock.inputStream)
            val status = input.read()
            if (status != 0) throw java.io.IOException("benbackupd could not read $absPath (status=$status)")
            var remaining = readU64(input)
            val total = remaining
            val buf = ByteArray(256 * 1024)
            while (remaining > 0) {
                val want = minOf(remaining, buf.size.toLong()).toInt()
                val n = input.read(buf, 0, want)
                if (n < 0) throw EOFException("short read on $absPath, $remaining left")
                sink.write(buf, 0, n)
                remaining -= n
            }
            return total
        }
    }

    private fun skipErrorRecord(input: DataInputStream) {
        // error record: u16 relLen, rel  (so we can log which path failed)
        readLenString(input)
    }

    private fun readU32(i: DataInputStream): Int {
        val b = ByteArray(4); i.readFully(b)
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).int
    }
    private fun readU64(i: DataInputStream): Long {
        val b = ByteArray(8); i.readFully(b)
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).long
    }
    private fun readI64(i: DataInputStream) = readU64(i)
    private fun readLenString(i: DataInputStream): String {
        val b = ByteArray(2); i.readFully(b)
        val len = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        if (len == 0) return ""
        val s = ByteArray(len); i.readFully(s)
        return String(s, Charsets.UTF_8)
    }

    companion object {
        // Must match the `socket` name in benbackupd.rc (init creates
        // /dev/socket/benbackupd; RESERVED namespace maps there).
        const val SOCKET_NAME = "benbackupd"
    }
}
