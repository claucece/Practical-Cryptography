// Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../crypto/internal.h"
#include "internal.h"
#include <iostream>

BSSL_NAMESPACE_BEGIN

// kMaxEmptyRecords is the number of consecutive, empty records that will be
// processed. Without this limit an attacker could send empty records at a
// faster rate than we can process and cause record processing to loop
// forever.
static const uint8_t kMaxEmptyRecords = 32;

// SURF
// kMaxSurfRecords bounds the TRUE-mode capture buffer. Termination is the
// peer's FIN, so nothing above TLS limits how much a hostile origin can stream
// before we stop, and every record costs a tag circuit.
static const size_t kMaxSurfRecords = 4096;

// kMaxEarlyDataSkipped is the maximum number of rejected early data bytes that
// will be skipped. Without this limit an attacker could send records at a
// faster rate than we can process and cause trial decryption to loop forever.
// This value should be slightly above kMaxEarlyDataAccepted, which is measured
// in plaintext.
static const size_t kMaxEarlyDataSkipped = 16384;

// kMaxWarningAlerts is the number of consecutive warning alerts that will be
// processed.
static const uint8_t kMaxWarningAlerts = 4;

// ssl_needs_record_splitting returns one if |ssl|'s current outgoing cipher
// state needs record-splitting and zero otherwise.
bool ssl_needs_record_splitting(const SSL *ssl) {
  return !CRYPTO_fuzzer_mode_enabled() &&
         !ssl->s3->aead_write_ctx->is_null_cipher() &&
         ssl_protocol_version(ssl) < TLS1_1_VERSION &&
         (ssl->mode & SSL_MODE_CBC_RECORD_SPLITTING) != 0 &&
         SSL_CIPHER_is_block_cipher(ssl->s3->aead_write_ctx->cipher());
}

size_t ssl_record_prefix_len(const SSL *ssl) {
  assert(!SSL_is_dtls(ssl));
  return SSL3_RT_HEADER_LENGTH + ssl->s3->aead_read_ctx->ExplicitNonceLen();
}

static ssl_open_record_t skip_early_data(SSL *ssl, uint8_t *out_alert,
                                         size_t consumed) {
  ssl->s3->early_data_skipped += consumed;
  if (ssl->s3->early_data_skipped < consumed) {
    ssl->s3->early_data_skipped = kMaxEarlyDataSkipped + 1;
  }

  if (ssl->s3->early_data_skipped > kMaxEarlyDataSkipped) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA);
    *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
    return ssl_open_record_error;
  }

  return ssl_open_record_discard;
}

static uint16_t tls_record_version(const SSL *ssl) {
  if (ssl->s3->version == 0) {
    // Before the version is determined, outgoing records use TLS 1.0 for
    // historical compatibility requirements.
    return TLS1_VERSION;
  }

  // TLS 1.3 freezes the record version at TLS 1.2. Previous ones use the
  // version itself.
  return ssl_protocol_version(ssl) >= TLS1_3_VERSION ? TLS1_2_VERSION
                                                     : ssl->s3->version;
}

bool surf_capture_ciphertext(SSL *ssl, const uint8_t *body, size_t body_len) {
  // The body is ciphertext || tag. Only the ciphertext is keystream-masked and
  // therefore block-indexable; folding the tag in would misalign every index
  // after the first record. The tag is kept separately for the later tag check.
  constexpr size_t kTagLen = 16;
  if (body_len < kTagLen) {
    return false;
  }
  const size_t ct_len = body_len - kTagLen;

  SSL::SurfRecord rec;
  if (!rec.ciphertext.CopyFrom(Span(body, ct_len))) {
    return false;
  }
  OPENSSL_memcpy(rec.tag.data(), body + ct_len, kTagLen);
  // Pre-increment: read_sequence is bumped after Open, and this value is what
  // fixes the GCM counter block for this record.
  rec.seq = ssl->s3->read_sequence;

  fprintf(stderr, "[surf_capture] seq=%llu body_len=%zu ct_len=%zu\n",
          (unsigned long long)ssl->s3->read_sequence, body_len, ct_len);

  ssl->surf_records.push_back(std::move(rec));
  return true;
}

ssl_open_record_t tls_open_record(SSL *ssl, uint8_t *out_type,
                                  Span<uint8_t> *out, size_t *out_consumed,
                                  uint8_t *out_alert, Span<uint8_t> in) {
  *out_consumed = 0;
  if (ssl->s3->read_shutdown == ssl_shutdown_close_notify) {
    return ssl_open_record_close_notify;
  }

  // If there is an unprocessed handshake message or we are already buffering
  // too much, stop before decrypting another handshake record.
  if (!tls_can_accept_handshake_data(ssl, out_alert)) {
    return ssl_open_record_error;
  }

  CBS cbs = CBS(in);

  // Decode the record header.
  uint8_t type;
  uint16_t version, ciphertext_len;
  if (!CBS_get_u8(&cbs, &type) ||      //
      !CBS_get_u16(&cbs, &version) ||  //
      !CBS_get_u16(&cbs, &ciphertext_len)) {
    *out_consumed = SSL3_RT_HEADER_LENGTH;
    return ssl_open_record_partial;
  }

  bool version_ok;
  if (ssl->s3->aead_read_ctx->is_null_cipher()) {
    // Only check the first byte. Enforcing beyond that can prevent decoding
    // version negotiation failure alerts.
    version_ok = (version >> 8) == SSL3_VERSION_MAJOR;
  } else {
    version_ok = version == tls_record_version(ssl);
  }

  if (!version_ok) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_VERSION_NUMBER);
    *out_alert = SSL_AD_PROTOCOL_VERSION;
    return ssl_open_record_error;
  }

  // Check the ciphertext length.
  if (ciphertext_len > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
    *out_alert = SSL_AD_RECORD_OVERFLOW;
    return ssl_open_record_error;
  }

  // Extract the body.
  CBS body;
  if (!CBS_get_bytes(&cbs, &body, ciphertext_len)) {
    *out_consumed = SSL3_RT_HEADER_LENGTH + (size_t)ciphertext_len;
    return ssl_open_record_partial;
  }

  // SURF: set when this record was decrypted from the attested keystream
  // rather than by the local AEAD, which holds only a placeholder key.
  bool surf_opened = false;

  Span<const uint8_t> header = in.subspan(0, SSL3_RT_HEADER_LENGTH);
  ssl_do_msg_callback(ssl, 0 /* read */, SSL3_RT_HEADER, header);


  if (ssl->verifier && ssl->s3->surf_traffic_keys_installed &&
      !ssl->s3->aead_read_ctx->is_null_cipher()) {
    if (!surf_capture_ciphertext(ssl, CBS_data(&body), CBS_len(&body))) {
      *out_alert = SSL_AD_INTERNAL_ERROR;
      return ssl_open_record_error;
    }

    // SURF TRUE mode: capture only. The prover holds k_c but not k_v, so no
    // record can be opened while it arrives: every tag circuit and the
    // decryption happen later, in true_surf_release. Returning discard means
    // "buffered in ssl->surf_records, nothing for the caller yet", the bytes
    // are not lost though.
    //
    // Running no 2PC here also keeps the origin socket unblocked: the tag
    // circuits no longer sit inside the read path.
    if (ssl->surf_true_mode) {
      *out_consumed = in.size() - CBS_len(&cbs);
      if (ssl->s3->read_sequence + 1 == 0) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
        *out_alert = SSL_AD_INTERNAL_ERROR;
        return ssl_open_record_error;
      }
      ssl->s3->read_sequence++;

       // We cannot recognise a close_notify as it arrives. The inner content
      // type is the last byte of the plaintext (RFC 8446 5.2), and nothing is
      // decryptable until KEY_RELEASE, which cannot happen until every record
      // has been submitted: you need the last record to know you are done, and
      // to be done to read the last record.
      //
      // Terminate on the peer's TCP FIN instead. It is visible below TLS, needs no
      // key, and since we send Connection: close the origin always closes; the
      // caller's read loop already breaks on n <= 0.
      if (ssl->surf_records.size() > kMaxSurfRecords) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
        *out_alert = SSL_AD_RECORD_OVERFLOW;
        return ssl_open_record_error;
      }
      return ssl_open_record_discard;
    }

    // Keystream: attest this record now: verify its tag, then derive its
    // keystream. Both run jointly with the verifier.
    if (ssl->surf_decrypt &&
        !ssl->surf_decrypt(ssl, ssl->surf_records.size() - 1)) {
      *out_alert = SSL_AD_INTERNAL_ERROR;
      return ssl_open_record_error;
    }

    // M_i = C_i XOR AES.Enc(k, IV + i). The prover holds no
    // server application traffic key, so the local AEAD cannot open this
    // record; ssl->keystream holds the blocks the circuit just produced, at
    // the global block offset derive_keystream advanced past. No tag check
    // here: the verifier already refuses to release keystream for a record whose tag
    // did not verify.
    constexpr size_t kTagLen = 16;
    const size_t ct_len = CBS_len(&body) - kTagLen;
    const size_t nblocks = (ct_len + 15) / 16;
    if (ssl->next_mask_index < nblocks ||
        ssl->keystream.size() < ssl->next_mask_index * 16) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      *out_alert = SSL_AD_INTERNAL_ERROR;
      return ssl_open_record_error;
    }
    const uint8_t *const ks =
        ssl->keystream.data() + (ssl->next_mask_index - nblocks) * 16;
    uint8_t *const pt = const_cast<uint8_t *>(CBS_data(&body));

    for (size_t i = 0; i < ct_len; i++) {
      pt[i] ^= ks[i];
    }

    fprintf(stderr, "[surf_open] seq=%llu ct_len=%zu inner=%02x first32=",
        (unsigned long long)ssl->s3->read_sequence, ct_len,
        (unsigned)(ct_len ? pt[ct_len - 1] : 0));

    for (size_t i = 0; i < 32 && i < ct_len; i++) {
      fprintf(stderr, "%c",
              (pt[i] >= 0x20 && pt[i] < 0x7f) ? pt[i] : '.');
    }
    fprintf(stderr, "\n");
    *out = Span(pt, ct_len);
    surf_opened = true;
  }

  *out_consumed = in.size() - CBS_len(&cbs);

  // In TLS 1.3, during the handshake, skip ChangeCipherSpec records.
  static const uint8_t kChangeCipherSpec[] = {SSL3_MT_CCS};
  if (ssl_has_final_version(ssl) &&
      ssl_protocol_version(ssl) >= TLS1_3_VERSION && SSL_in_init(ssl) &&
      type == SSL3_RT_CHANGE_CIPHER_SPEC &&
      Span<const uint8_t>(body) == kChangeCipherSpec) {
    ssl->s3->empty_record_count++;
    if (ssl->s3->empty_record_count > kMaxEmptyRecords) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_EMPTY_FRAGMENTS);
      *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
      return ssl_open_record_error;
    }
    return ssl_open_record_discard;
  }

  // Skip early data received when expecting a second ClientHello if we rejected
  // 0RTT.
  if (ssl->s3->skip_early_data &&                  //
      ssl->s3->aead_read_ctx->is_null_cipher() &&  //
      type == SSL3_RT_APPLICATION_DATA) {
    return skip_early_data(ssl, out_alert, *out_consumed);
  }

  // Ensure the sequence number update does not overflow.
  if (ssl->s3->read_sequence + 1 == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return ssl_open_record_error;
  }

  // Decrypt the body in-place.
  if (!surf_opened) {
    if (ssl->verifier && ssl->aes_decrypt &&
          !ssl->s3->aead_read_ctx->is_null_cipher() &&
          !ssl->s3->aead_read_ctx->Open(out, type, version, ssl->s3->read_sequence, header,
                                        Span(const_cast<uint8_t *>(CBS_data(&body)), CBS_len(&body)))) {
      if (ssl->s3->skip_early_data && !ssl->s3->aead_read_ctx->is_null_cipher()) {
        ERR_clear_error();
        return skip_early_data(ssl, out_alert, *out_consumed);
      }

      OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
      *out_alert = SSL_AD_BAD_RECORD_MAC;
      return ssl_open_record_error;
    } else {
      // Decrypt the body in-place.
      if (!ssl->s3->aead_read_ctx->Open(out, type, version, ssl->s3->read_sequence, header,
                                        Span(const_cast<uint8_t *>(CBS_data(&body)), CBS_len(&body)))) {
        if (ssl->s3->skip_early_data &&
            !ssl->s3->aead_read_ctx->is_null_cipher()) {
          ERR_clear_error();
          return skip_early_data(ssl, out_alert, *out_consumed);
        }

        OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        *out_alert = SSL_AD_BAD_RECORD_MAC;
        return ssl_open_record_error;
      }
    }
  }

  ssl->s3->skip_early_data = false;
  ssl->s3->read_sequence++;

  // TLS 1.3 hides the record type inside the encrypted data.
  bool has_padding = !ssl->s3->aead_read_ctx->is_null_cipher() &&
                     ssl_protocol_version(ssl) >= TLS1_3_VERSION;

  // If there is padding, the plaintext limit includes the padding, but includes
  // extra room for the inner content type.
  size_t plaintext_limit =
      has_padding ? SSL3_RT_MAX_PLAIN_LENGTH + 1 : SSL3_RT_MAX_PLAIN_LENGTH;
  if (out->size() > plaintext_limit) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    *out_alert = SSL_AD_RECORD_OVERFLOW;
    return ssl_open_record_error;
  }

  if (has_padding) {
    // The outer record type is always application_data.
    if (type != SSL3_RT_APPLICATION_DATA) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_OUTER_RECORD_TYPE);
      *out_alert = SSL_AD_DECODE_ERROR;
      return ssl_open_record_error;
    }

    do {
      if (out->empty()) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        *out_alert = SSL_AD_DECRYPT_ERROR;
        return ssl_open_record_error;
      }
      type = out->back();
      *out = out->subspan(0, out->size() - 1);
    } while (type == 0);
  }

  // Limit the number of consecutive empty records.
  if (out->empty()) {
    ssl->s3->empty_record_count++;
    if (ssl->s3->empty_record_count > kMaxEmptyRecords) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_EMPTY_FRAGMENTS);
      *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
      return ssl_open_record_error;
    }
    // Apart from the limit, empty records are returned up to the caller. This
    // allows the caller to reject records of the wrong type.
  } else {
    ssl->s3->empty_record_count = 0;
  }

  if (type == SSL3_RT_ALERT) {
    return ssl_process_alert(ssl, out_alert, *out);
  }

  // Handshake messages may not interleave with any other record type.
  if (type != SSL3_RT_HANDSHAKE &&  //
      tls_has_unprocessed_handshake_data(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);
    *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
    return ssl_open_record_error;
  }

  ssl->s3->warning_alert_count = 0;

  *out_type = type;
  return ssl_open_record_success;
}

static bool do_seal_record(SSL *ssl, uint8_t *out_prefix, uint8_t *out,
                           uint8_t *out_suffix, uint8_t type, const uint8_t *in,
                           const size_t in_len) {
  SSLAEADContext *aead = ssl->s3->aead_write_ctx.get();
  uint8_t *extra_in = NULL;
  size_t extra_in_len = 0;
  if (!aead->is_null_cipher() && ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
    // TLS 1.3 hides the actual record type inside the encrypted data.
    extra_in = &type;
    extra_in_len = 1;
  }

  size_t suffix_len, ciphertext_len;
  if (!aead->SuffixLen(&suffix_len, in_len, extra_in_len) ||
      !aead->CiphertextLen(&ciphertext_len, in_len, extra_in_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return false;
  }

  assert(in == out || !buffers_alias(in, in_len, out, in_len));
  assert(!buffers_alias(in, in_len, out_prefix, ssl_record_prefix_len(ssl)));
  assert(!buffers_alias(in, in_len, out_suffix, suffix_len));

  if (extra_in_len) {
    out_prefix[0] = SSL3_RT_APPLICATION_DATA;
  } else {
    out_prefix[0] = type;
  }

  uint16_t record_version = tls_record_version(ssl);
  out_prefix[1] = record_version >> 8;
  out_prefix[2] = record_version & 0xff;
  out_prefix[3] = ciphertext_len >> 8;
  out_prefix[4] = ciphertext_len & 0xff;
  Span<const uint8_t> header = Span(out_prefix, SSL3_RT_HEADER_LENGTH);

  // Ensure the sequence number update does not overflow.
  if (ssl->s3->write_sequence + 1 == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
    return false;
  }

  if (!aead->SealScatter(out_prefix + SSL3_RT_HEADER_LENGTH, out, out_suffix,
                         out_prefix[0], record_version, ssl->s3->write_sequence,
                         header, in, in_len, extra_in, extra_in_len)) {
    return false;
  }

  ssl->s3->write_sequence++;
  ssl_do_msg_callback(ssl, 1 /* write */, SSL3_RT_HEADER, header);
  return true;
}

static size_t tls_seal_scatter_prefix_len(const SSL *ssl, uint8_t type,
                                          size_t in_len) {
  size_t ret = SSL3_RT_HEADER_LENGTH;
  if (type == SSL3_RT_APPLICATION_DATA && in_len > 1 &&
      ssl_needs_record_splitting(ssl)) {
    // In the case of record splitting, the 1-byte record (of the 1/n-1 split)
    // will be placed in the prefix, as will four of the five bytes of the
    // record header for the main record. The final byte will replace the first
    // byte of the plaintext that was used in the small record.
    ret += ssl_cipher_get_record_split_len(ssl->s3->aead_write_ctx->cipher());
    ret += SSL3_RT_HEADER_LENGTH - 1;
  } else {
    ret += ssl->s3->aead_write_ctx->ExplicitNonceLen();
  }
  return ret;
}

static bool tls_seal_scatter_suffix_len(const SSL *ssl, size_t *out_suffix_len,
                                        uint8_t type, size_t in_len) {
  size_t extra_in_len = 0;
  if (!ssl->s3->aead_write_ctx->is_null_cipher() &&
      ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
    // TLS 1.3 adds an extra byte for encrypted record type.
    extra_in_len = 1;
  }
  // clang-format off
  if (type == SSL3_RT_APPLICATION_DATA &&
      in_len > 1 &&
      ssl_needs_record_splitting(ssl)) {
    // With record splitting enabled, the first byte gets sealed into a separate
    // record which is written into the prefix.
    in_len -= 1;
  }
  // clang-format on
  return ssl->s3->aead_write_ctx->SuffixLen(out_suffix_len, in_len,
                                            extra_in_len);
}

// tls_seal_scatter_record seals a new record of type |type| and body |in| and
// splits it between |out_prefix|, |out|, and |out_suffix|. Exactly
// |tls_seal_scatter_prefix_len| bytes are written to |out_prefix|, |in_len|
// bytes to |out|, and |tls_seal_scatter_suffix_len| bytes to |out_suffix|. It
// returns one on success and zero on error. If enabled,
// |tls_seal_scatter_record| implements TLS 1.0 CBC 1/n-1 record splitting and
// may write two records concatenated.
static bool tls_seal_scatter_record(SSL *ssl, uint8_t *out_prefix, uint8_t *out,
                                    uint8_t *out_suffix, uint8_t type,
                                    const uint8_t *in, size_t in_len) {
  if (type == SSL3_RT_APPLICATION_DATA && in_len > 1 &&
      ssl_needs_record_splitting(ssl)) {
    assert(ssl->s3->aead_write_ctx->ExplicitNonceLen() == 0);
    const size_t prefix_len = SSL3_RT_HEADER_LENGTH;

    // Write the 1-byte fragment into |out_prefix|.
    uint8_t *split_body = out_prefix + prefix_len;
    uint8_t *split_suffix = split_body + 1;

    if (!do_seal_record(ssl, out_prefix, split_body, split_suffix, type, in,
                        1)) {
      return false;
    }

    size_t split_record_suffix_len;
    if (!ssl->s3->aead_write_ctx->SuffixLen(&split_record_suffix_len, 1, 0)) {
      assert(false);
      return false;
    }
    const size_t split_record_len = prefix_len + 1 + split_record_suffix_len;
    assert(SSL3_RT_HEADER_LENGTH + ssl_cipher_get_record_split_len(
                                       ssl->s3->aead_write_ctx->cipher()) ==
           split_record_len);

    // Write the n-1-byte fragment. The header gets split between |out_prefix|
    // (header[:-1]) and |out| (header[-1:]).
    uint8_t tmp_prefix[SSL3_RT_HEADER_LENGTH];
    if (!do_seal_record(ssl, tmp_prefix, out + 1, out_suffix, type, in + 1,
                        in_len - 1)) {
      return false;
    }
    assert(tls_seal_scatter_prefix_len(ssl, type, in_len) ==
           split_record_len + SSL3_RT_HEADER_LENGTH - 1);
    OPENSSL_memcpy(out_prefix + split_record_len, tmp_prefix,
                   SSL3_RT_HEADER_LENGTH - 1);
    OPENSSL_memcpy(out, tmp_prefix + SSL3_RT_HEADER_LENGTH - 1, 1);
    return true;
  }

  return do_seal_record(ssl, out_prefix, out, out_suffix, type, in, in_len);
}

bool tls_seal_record(SSL *ssl, uint8_t *out, size_t *out_len,
                     size_t max_out_len, uint8_t type, const uint8_t *in,
                     size_t in_len) {
  // SURF: on the MPC path the client traffic key is secret-shared, so an
  // application record cannot be sealed locally. surf_encrypt runs Algorithm 1
  // jointly with the verifier and returns the whole record.
  //
  // Gated on |type| being application data: handshake records (the client
  // Finished, sealed at add_message time under the handshake key) and alerts
  // still take the normal path. Gated on surf_traffic_keys_installed for the
  // same reason as the capture path in tls_open_record.
  const bool surf_seal_type =
      type == SSL3_RT_APPLICATION_DATA ||
      (type == SSL3_RT_HANDSHAKE && ssl->surf_mode == SurfMode::Rotate);
  if (surf_seal_type && ssl->verifier && ssl->surf_encrypt &&
      ssl->s3->surf_traffic_keys_installed) {
    // Matches the check do_seal_record would have made.
    if (ssl->s3->write_sequence + 1 == 0) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
      return false;
    }

    bssl::Array<uint8_t> record;
    if (!ssl->surf_encrypt(ssl, Span(in, in_len), type, record)) {
      return false;
    }
    if (record.size() > max_out_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BUFFER_TOO_SMALL);
      return false;
    }

    OPENSSL_memcpy(out, record.data(), record.size());
    *out_len = record.size();
    ssl->s3->write_sequence++;
    ssl_do_msg_callback(ssl, 1 /* write */, SSL3_RT_HEADER,
                        Span(out, SSL3_RT_HEADER_LENGTH));
    return true;
  }

  if (buffers_alias(in, in_len, out, max_out_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_OUTPUT_ALIASES_INPUT);
    return false;
  }

  const size_t prefix_len = tls_seal_scatter_prefix_len(ssl, type, in_len);
  size_t suffix_len;
  if (!tls_seal_scatter_suffix_len(ssl, &suffix_len, type, in_len)) {
    return false;
  }
  if (in_len + prefix_len < in_len ||
      prefix_len + in_len + suffix_len < prefix_len + in_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return false;
  }
  if (max_out_len < in_len + prefix_len + suffix_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BUFFER_TOO_SMALL);
    return false;
  }

  uint8_t *prefix = out;
  uint8_t *body = out + prefix_len;
  uint8_t *suffix = body + in_len;
  if (!tls_seal_scatter_record(ssl, prefix, body, suffix, type, in, in_len)) {
    return false;
  }

  *out_len = prefix_len + in_len + suffix_len;
  return true;
}

enum ssl_open_record_t ssl_process_alert(SSL *ssl, uint8_t *out_alert,
                                         Span<const uint8_t> in) {
  // Alerts records may not contain fragmented or multiple alerts.
  if (in.size() != 2) {
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ALERT);
    return ssl_open_record_error;
  }

  ssl_do_msg_callback(ssl, 0 /* read */, SSL3_RT_ALERT, in);

  const uint8_t alert_level = in[0];
  const uint8_t alert_descr = in[1];

  uint16_t alert = (alert_level << 8) | alert_descr;
  ssl_do_info_callback(ssl, SSL_CB_READ_ALERT, alert);

  if (alert_level == SSL3_AL_WARNING) {
    if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
      ssl->s3->read_shutdown = ssl_shutdown_close_notify;
      return ssl_open_record_close_notify;
    }

    // Warning alerts do not exist in TLS 1.3, but RFC 8446 section 6.1
    // continues to define user_canceled as a signal to cancel the handshake,
    // without specifying how to handle it. JDK11 misuses it to signal
    // full-duplex connection close after the handshake. As a workaround, skip
    // user_canceled as in TLS 1.2. This matches NSS and OpenSSL.
    if (ssl_has_final_version(ssl) &&
        ssl_protocol_version(ssl) >= TLS1_3_VERSION &&
        alert_descr != SSL_AD_USER_CANCELLED) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ALERT);
      return ssl_open_record_error;
    }

    ssl->s3->warning_alert_count++;
    if (ssl->s3->warning_alert_count > kMaxWarningAlerts) {
      *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_WARNING_ALERTS);
      return ssl_open_record_error;
    }
    return ssl_open_record_discard;
  }

  if (alert_level == SSL3_AL_FATAL) {
    OPENSSL_PUT_ERROR(SSL, SSL_AD_REASON_OFFSET + alert_descr);
    ERR_add_error_dataf("SSL alert number %d", alert_descr);
    *out_alert = 0;  // No alert to send back to the peer.
    return ssl_open_record_error;
  }

  *out_alert = SSL_AD_ILLEGAL_PARAMETER;
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_ALERT_TYPE);
  return ssl_open_record_error;
}

BSSL_NAMESPACE_END

using namespace bssl;

size_t SSL_max_seal_overhead(const SSL *ssl) {
  if (SSL_is_dtls(ssl)) {
    // TODO(crbug.com/381113363): Use the 0-RTT epoch if writing 0-RTT.
    return dtls_max_seal_overhead(ssl, ssl->d1->write_epoch.epoch());
  }

  size_t ret = SSL3_RT_HEADER_LENGTH;
  ret += ssl->s3->aead_write_ctx->MaxOverhead();
  // TLS 1.3 needs an extra byte for the encrypted record type.
  if (!ssl->s3->aead_write_ctx->is_null_cipher() &&
      ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
    ret += 1;
  }
  if (ssl_needs_record_splitting(ssl)) {
    ret *= 2;
  }
  return ret;
}
