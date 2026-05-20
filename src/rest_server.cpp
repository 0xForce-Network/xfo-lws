// Copyright (c) 2018-2020, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#include "rest_server.h"

#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_static_buffer.hpp>
#include <boost/beast/core/string.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/version.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/optional/optional.hpp>
#include <boost/range/counting_range.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/lock_types.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/tss.hpp>
#include <boost/utility/string_ref.hpp>
#include <chrono>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "byte_stream.h"          // monero/contrib/epee/include
#include "common/error.h"          // monero/src
#include "common/expect.h"         // monero/src
#include "config.h"
#include "crypto/crypto.h"         // monero/src
#include "crypto/wallet/crypto.h"  // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "cryptonote_config.h"     // monero/src
#include "db/data.h"
#include "db/multisig_store.h"
#include "db/storage.h"
#include "db/string.h"
#include "error.h"
#include "lmdb/util.h"             // monero/src
#include "net/http/client.h"
#include "net/http/slice_body.h"
#include "net/net_parse_helpers.h" // monero/contrib/epee/include
#include "net/net_ssl.h"           // monero/contrib/epee/include
#include "net/net_utils_base.h"    // monero/contrib/epee/include
#include "net/zmq.h"               // monero/src
#include "net/zmq_async.h"
#include "rpc/admin.h"
#include "rpc/client.h"
#include "rpc/daemon_messages.h"   // monero/src
#include "rpc/daemon_zmq.h"
#include "rpc/json.h"
#include "rpc/light_wallet.h"
#include "rpc/multisig.h"
#include "rpc/rates.h"
#include "rpc/webhook.h"
#include "string_tools.h"          // monero/contrib/epee/include
#include "util/gamma_picker.h"
#include "util/random_outputs.h"
#include "util/source_location.h"
#include "util/transactions.h"
#include "wire/adapted/crypto.h"
#include "wire/json.h"

namespace lws
{
  struct runtime_options
  {
    const std::uint32_t max_subaddresses;
    const epee::net_utils::ssl_verification_t webhook_verify;
    const bool disable_admin_auth;
    const bool auto_accept_creation;
    const bool auto_accept_import;
    const bool debug;
    const bool auto_rescan_after_key_images;
    const std::uint64_t auto_rescan_depth;
    const std::uint64_t auto_rescan_min_confirmed_spends;
  };

  struct rest_server_data
  {
    boost::asio::io_context io;
    const db::storage disk;
    const rpc::client client;
    const runtime_options options;
    db::multisig_store multisig;
    std::vector<net::zmq::async_client> clients;
    net::http::client webhook_client;
    boost::mutex sync;

    rest_server_data(db::storage disk, rpc::client client, runtime_options options)
      : io(),
        disk(std::move(disk)),
        client(std::move(client)),
        options(std::move(options)),
        multisig("/var/data/xfo-lws-db/multisig_store.json"),
        webhook_client(options.webhook_verify),
        clients(),
        sync()
    {}

    expect<net::zmq::async_client> get_async_client()
    {
      boost::unique_lock<boost::mutex> lock{sync};
      if (!clients.empty())
      {
        net::zmq::async_client out{std::move(clients.back())};
        clients.pop_back();
        return out;
      }
      lock.unlock();
      return client.make_async_client(io);
    }

    void store_async_client(net::zmq::async_client&& client)
    {
      const boost::lock_guard<boost::mutex> lock{sync};
      client.close = false;
      clients.push_back(std::move(client));
    }
  };

  namespace
  {
    namespace http = epee::net_utils::http;
    constexpr const std::size_t http_parser_buffer_size = 16 * 1024;
    constexpr const std::chrono::seconds zmq_reconnect_backoff{10};
    constexpr const std::chrono::seconds rest_handshake_timeout{5};
    constexpr const std::chrono::seconds rest_request_timeout_initial{5};
    constexpr const std::chrono::minutes rest_request_timeout_login{5};
    constexpr const std::chrono::seconds rest_response_timeout{15};

    //! `/daemon_status` and `get_unspent_outs` caches ZMQ result for this long
    constexpr const std::chrono::seconds daemon_cache_timeout{5};
    constexpr const std::chrono::seconds txpool_overlay_cache_timeout{2};

    constexpr const unsigned max_ring_size = 20;
    constexpr const unsigned max_rings = 150;

    db::block_id select_auto_rescan_height(const db::account& account, const std::uint64_t depth) noexcept
    {
      if (depth == 0)
        return account.start_height;
      const std::uint64_t scan_height = std::uint64_t(account.scan_height);
      const std::uint64_t target = scan_height <= depth ? 0 : scan_height - depth;
      return db::block_id(std::max(target, std::uint64_t(account.start_height)));
    }

    void maybe_auto_rescan_after_key_images(rest_server_data& data, const db::account& account, const db::storage::import_key_images_result& result)
    {
      const runtime_options& options = data.options;
      if (!options.auto_rescan_after_key_images)
      {
        if (options.debug)
          MINFO("/import_key_images auto_rescan skipped: reason=disabled account_id=" << unsigned(account.id));
        return;
      }

      if (std::uint64_t(result.imported) < options.auto_rescan_min_confirmed_spends)
      {
        if (options.debug)
          MINFO("/import_key_images auto_rescan skipped: reason=imported_below_threshold account_id=" << unsigned(account.id)
                << " imported=" << std::uint64_t(result.imported)
                << " confirmed_spends=" << std::uint64_t(result.confirmed_spends)
                << " exact_source_inserted=" << result.exact_source_inserted
                << " min_confirmed_spends=" << options.auto_rescan_min_confirmed_spends);
        return;
      }

      const db::block_id target = select_auto_rescan_height(account, options.auto_rescan_depth);
      if (account.scan_height <= target)
      {
        if (options.debug)
          MINFO("/import_key_images auto_rescan skipped: reason=already_at_or_before_target account_id=" << unsigned(account.id)
                << " scan_height=" << std::uint64_t(account.scan_height)
                << " target_height=" << std::uint64_t(target)
                << " depth=" << options.auto_rescan_depth);
        return;
      }

      const std::array<db::account_address, 1> addresses{{account.address}};
      const auto rescanned = data.disk.clone().rescan(target, epee::to_span(addresses));
      if (!rescanned)
      {
        MWARNING("/import_key_images auto_rescan failed: account_id=" << unsigned(account.id)
                 << " from_scan_height=" << std::uint64_t(account.scan_height)
                 << " target_height=" << std::uint64_t(target)
                 << " error=" << rescanned.error().message());
        return;
      }

      MINFO("/import_key_images auto_rescan triggered: account_id=" << unsigned(account.id)
            << " from_scan_height=" << std::uint64_t(account.scan_height)
            << " target_height=" << std::uint64_t(target)
            << " depth=" << options.auto_rescan_depth
            << " confirmed_spends=" << std::uint64_t(result.confirmed_spends)
            << " imported=" << std::uint64_t(result.imported)
            << " updated_addresses=" << rescanned->size());
    }

    struct connection_data
    {
      rest_server_data* const global; //!< Valid for lifetime of server
      boost::beast::http::verb last_verb;
      bool passed_login; //!< True iff a login via viewkey was successful

      explicit connection_data(rest_server_data* global) noexcept
        : global(global), last_verb(boost::beast::http::verb::unknown), passed_login(false)
      {}

      //! \return Next request timeout, based on login status
      std::chrono::seconds get_request_timeout() const noexcept
      {
        return passed_login ?
          rest_request_timeout_login : rest_request_timeout_initial;
      }
    };

    struct copyable_slice
    {
      epee::byte_slice value;

      copyable_slice(epee::byte_slice value) noexcept
        : value(std::move(value))
      {}

      copyable_slice(copyable_slice&&) = default;
      copyable_slice(const copyable_slice& rhs) noexcept
        : value(rhs.value.clone())
      {}

      copyable_slice& operator=(copyable_slice&&) = default;
      copyable_slice& operator=(const copyable_slice& rhs) noexcept
      {
        if (this != std::addressof(rhs))
          value = rhs.value.clone();
        return *this;
      }
    };
    using async_complete = void(expect<copyable_slice>);

    struct key_image_less
    {
      bool operator()(const crypto::key_image& lhs, const crypto::key_image& rhs) const noexcept
      {
        return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(crypto::key_image)) < 0;
      }
    };

    bool key_image_equal(const crypto::key_image& lhs, const crypto::key_image& rhs) noexcept
    {
      return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(crypto::key_image)) == 0;
    }

    bool public_key_equal(const crypto::public_key& lhs, const crypto::public_key& rhs) noexcept
    {
      return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(crypto::public_key)) == 0;
    }

    constexpr const std::uint64_t pending_spend_ttl_seconds = 24 * 60 * 60;
    constexpr const char* lws_spent_state_patch_marker = "lws-spent-state-v20260520-key-image-dedup-exact-source";

    std::uint64_t unix_timestamp_now() noexcept
    {
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
      );
      return now.count() < 0 ? 0 : std::uint64_t(now.count());
    }

    bool output_id_equal(const db::output_id& lhs, const db::output_id& rhs) noexcept
    {
      return lhs.high == rhs.high && lhs.low == rhs.low;
    }

    bool pending_spend_matches_output(const db::pending_spend& pending, const db::output& output) noexcept
    {
      return output_id_equal(pending.source, output.spend_meta.id) &&
        pending.out_index == output.spend_meta.index &&
        pending.tx_hash == output.link.tx_hash &&
        public_key_equal(pending.pub, output.pub);
    }

    struct confirmed_spend_choice
    {
      db::spend spend;
      db::output::spend_meta_ meta;
      db::output_id source;
      bool imported_source;
    };

    struct output_id_less
    {
      bool operator()(const db::output_id& lhs, const db::output_id& rhs) const noexcept
      {
        if (lhs.high != rhs.high)
          return lhs.high < rhs.high;
        return lhs.low < rhs.low;
      }
    };

    bool should_replace_confirmed_spend_choice(
      const confirmed_spend_choice& current,
      const confirmed_spend_choice& candidate) noexcept
    {
      if (current.imported_source != candidate.imported_source)
        return candidate.imported_source;

      if (current.meta.amount != candidate.meta.amount)
        return current.meta.amount < candidate.meta.amount;

      const output_id_less less{};
      return less(candidate.source, current.source);
    }

    const db::output* find_output_by_id(const std::vector<db::output>& outputs, const db::output_id& id) noexcept
    {
      for (const db::output& output : outputs)
      {
        if (output_id_equal(output.spend_meta.id, id))
          return std::addressof(output);
      }
      return nullptr;
    }

    const db::output* find_output_by_imported_source(
      const std::vector<db::output>& outputs,
      const std::map<crypto::key_image, db::key_image_source, key_image_less>& imported_sources,
      const crypto::key_image& image) noexcept
    {
      const auto source = imported_sources.find(image);
      if (source == imported_sources.end())
        return nullptr;

      for (const db::output& output : outputs)
      {
        if (output_id_equal(output.spend_meta.id, source->second.source) &&
            output.spend_meta.index == source->second.out_index &&
            public_key_equal(output.pub, source->second.pub) &&
            std::memcmp(std::addressof(output.link.tx_hash), std::addressof(source->second.tx_hash), sizeof(crypto::hash)) == 0)
          return std::addressof(output);
      }
      return nullptr;
    }

    expect<std::vector<crypto::key_image>> get_output_spend_images(db::storage_reader& reader, const db::output_id& id)
    {
      auto images = reader.get_images(id);
      if (!images)
        return images.error();

      std::vector<crypto::key_image> out{};
      out.reserve(images->count());
      for (const db::key_image& image : images->make_range())
        out.push_back(image.value);
      return out;
    }

    bool has_confirmed_spend_image(
      const std::vector<crypto::key_image>& images,
      const std::set<crypto::key_image, key_image_less>& confirmed_images) noexcept
    {
      for (const crypto::key_image& image : images)
      {
        if (confirmed_images.count(image) != 0)
          return true;
      }
      return false;
    }

    struct hash_less
    {
      bool operator()(const crypto::hash& lhs, const crypto::hash& rhs) const noexcept
      {
        return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(crypto::hash)) < 0;
      }
    };

    bool is_ringct_output(const db::output& output) noexcept
    {
      return (std::uint8_t(db::unpack(output.extra).first) & std::uint8_t(db::extra::ringct_output)) != 0;
    }

    struct txpool_overlay_match
    {
      db::output output;
      crypto::hash tx_hash;
      std::uint64_t daemon_receive_time;
    };

    bool hash_equal(const crypto::hash& lhs, const crypto::hash& rhs) noexcept
    {
      return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(crypto::hash)) == 0;
    }

    bool output_exists_in_rows(const std::vector<db::output>& rows, const txpool_overlay_match& match) noexcept
    {
      for (const db::output& output : rows)
      {
        if (hash_equal(output.link.tx_hash, match.output.link.tx_hash) && output.spend_meta.index == match.output.spend_meta.index)
          return true;
      }
      return false;
    }

    expect<std::vector<cryptonote::rpc::tx_in_pool>> fetch_txpool_transactions_cached(
      const rpc::client& daemon_client)
    {
      static boost::mutex sync;
      static rpc::client txpool_client{};
      static bool txpool_client_ready = false;
      static bool cached_valid = false;
      static std::chrono::steady_clock::time_point cached_at{};
      static std::vector<cryptonote::rpc::tx_in_pool> cached_transactions{};

      const auto now = std::chrono::steady_clock::now();
      const boost::lock_guard<boost::mutex> lock{sync};
      if (cached_valid && now - cached_at < txpool_overlay_cache_timeout)
        return cached_transactions;

      if (!txpool_client_ready)
      {
        auto rpc_client = daemon_client.clone();
        if (!rpc_client)
          return rpc_client.error();
        txpool_client = std::move(*rpc_client);
        txpool_client_ready = true;
      }

      cryptonote::rpc::GetTransactionPool::Request txpool_req{};
      expect<void> sent = txpool_client.send(rpc::client::make_message("get_transaction_pool", txpool_req), std::chrono::seconds{10});
      if (!sent)
      {
        txpool_client = rpc::client{};
        txpool_client_ready = false;
        cached_valid = false;
        return sent.error();
      }

      auto txpool_raw = txpool_client.get_message(std::chrono::seconds{15});
      if (!txpool_raw)
      {
        txpool_client = rpc::client{};
        txpool_client_ready = false;
        cached_valid = false;
        return txpool_raw.error();
      }

      auto txpool = rpc::parse_json_response<rpc::get_transaction_pool>(std::move(*txpool_raw));
      if (!txpool)
      {
        cached_valid = false;
        return txpool.error();
      }

      cached_transactions = std::move(txpool->transactions);
      cached_at = now;
      cached_valid = true;
      return cached_transactions;
    }

    expect<std::vector<txpool_overlay_match>> fetch_txpool_incoming_overlay(
      const db::account& account,
      const rpc::client& daemon_client,
      const bool debug)
    {
      auto txpool_transactions = fetch_txpool_transactions_cached(daemon_client);
      if (!txpool_transactions)
        return txpool_transactions.error();

      std::vector<txpool_overlay_match> matches{};
      std::size_t inspected_outputs = 0;
      std::size_t matched_outputs = 0;
      const std::uint64_t now = unix_timestamp_now();
      crypto::secret_key view_key{};
      static_assert(sizeof(view_key) == sizeof(account.key), "different size keys");
      std::memcpy(std::addressof(unwrap(unwrap(view_key))), std::addressof(account.key), sizeof(view_key));
      for (const auto& tx_entry : *txpool_transactions)
      {
        const cryptonote::transaction& tx = tx_entry.tx;
        if (2 < tx.version)
          continue;
        const std::uint64_t overlay_timestamp = tx_entry.receive_time ? tx_entry.receive_time : now;

        cryptonote::tx_extra_pub_key key{};
        cryptonote::tx_extra_nonce extra_nonce{};
        cryptonote::tx_extra_additional_pub_keys additional_tx_pub_keys{};
        {
          std::vector<cryptonote::tx_extra_field> extra{};
          cryptonote::parse_tx_extra(tx.extra, extra);
          if (!cryptonote::find_tx_extra_field_by_type(extra, key))
            continue;
          cryptonote::find_tx_extra_field_by_type(extra, extra_nonce);
          cryptonote::find_tx_extra_field_by_type(extra, additional_tx_pub_keys);
        }

        crypto::key_derivation derived{};
        if (!crypto::wallet::generate_key_derivation(key.pub_key, view_key, derived))
          continue;

        std::vector<crypto::key_derivation> additional_derivations{};
        if (additional_tx_pub_keys.data.size() == tx.vout.size())
        {
          additional_derivations.resize(tx.vout.size());
          bool additional_ok = true;
          for (std::size_t index = 0; index < tx.vout.size(); ++index)
          {
            if (!crypto::wallet::generate_key_derivation(additional_tx_pub_keys.data[index], view_key, additional_derivations[index]))
            {
              additional_ok = false;
              break;
            }
          }
          if (!additional_ok)
            additional_derivations.clear();
        }

        db::extra ext{};
        std::uint32_t mixin = 0;
        for (const auto& in : tx.vin)
        {
          const cryptonote::txin_to_key* const in_data = boost::get<cryptonote::txin_to_key>(std::addressof(in));
          if (in_data)
          {
            mixin = boost::numeric_cast<std::uint32_t>(std::max(std::size_t(1), in_data->key_offsets.size()) - 1);
          }
          else if (boost::get<cryptonote::txin_gen>(std::addressof(in)))
            ext = db::extra(ext | db::coinbase_output);
        }

        for (std::size_t index = 0; index < tx.vout.size(); ++index)
        {
          ++inspected_outputs;
          crypto::public_key out_pub_key{};
          if (!cryptonote::get_output_public_key(tx.vout[index], out_pub_key))
            continue;

          boost::optional<crypto::view_tag> view_tag_opt = cryptonote::get_output_view_tag(tx.vout[index]);
          const bool found_tag =
            (!additional_derivations.empty() && cryptonote::out_can_be_to_acc(view_tag_opt, additional_derivations.at(index), index)) ||
            cryptonote::out_can_be_to_acc(view_tag_opt, derived, index);
          if (!found_tag)
            continue;

          bool found_pub = false;
          crypto::key_derivation active_derived{};
          crypto::public_key active_pub{};
          for (std::size_t attempt = 0; attempt < 2; ++attempt)
          {
            if (attempt == 0)
            {
              active_derived = derived;
              active_pub = key.pub_key;
            }
            else if (!additional_derivations.empty())
            {
              active_derived = additional_derivations.at(index);
              active_pub = additional_tx_pub_keys.data.at(index);
            }
            else
              break;

            crypto::public_key derived_pub{};
            if (!crypto::wallet::derive_subaddress_public_key(out_pub_key, active_derived, index, derived_pub))
              continue;

            if (account.address.spend_public == derived_pub)
            {
              found_pub = true;
              break;
            }
          }

          if (!found_pub)
            continue;

          std::uint64_t amount = tx.vout[index].amount;
          rct::key mask = rct::identity();
          db::extra output_ext = ext;
          if (!amount && !(output_ext & db::coinbase_output) && 1 < tx.version)
          {
            if (tx.rct_signatures.outPk.size() <= index || tx.rct_signatures.ecdhInfo.size() <= index)
              continue;
            const bool bulletproof2 = (rct::RCTTypeBulletproof2 <= tx.rct_signatures.type);
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk.at(index).mask,
              tx.rct_signatures.ecdhInfo.at(index),
              active_derived,
              index,
              bulletproof2
            );
            if (!decrypted)
              continue;
            amount = decrypted->first;
            mask = decrypted->second;
            output_ext = db::extra(output_ext | db::ringct_output);
          }
          else if (1 < tx.version)
            output_ext = db::extra(output_ext | db::ringct_output);

          db::output::payment_id_ payment_id{};
          std::uint8_t payment_id_size = 0;
          if (!extra_nonce.nonce.empty() && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id.short_))
          {
            payment_id_size = sizeof(crypto::hash8);
            lws::decrypt_payment_id(payment_id.short_, active_derived);
          }

          crypto::hash tx_prefix_hash{};
          cryptonote::get_transaction_prefix_hash(tx, tx_prefix_hash);
          matches.push_back(txpool_overlay_match{
            db::output{
              db::transaction_link{db::block_id::txpool, tx_entry.tx_hash},
              db::output::spend_meta_{
                db::output_id::txpool(),
                amount,
                mixin,
                boost::numeric_cast<std::uint32_t>(index),
                active_pub
              },
              overlay_timestamp,
              tx.unlock_time,
              tx_prefix_hash,
              out_pub_key,
              mask,
              {0, 0, 0, 0, 0, 0, 0},
              db::pack(output_ext, payment_id_size),
              payment_id,
              cryptonote::get_tx_fee(tx),
              db::address_index{db::major_index::primary, db::minor_index::primary}
            },
            tx_entry.tx_hash,
            tx_entry.receive_time
          });
          if (debug)
          {
            MINFO("lws-txpool-overlay-time-diagnostic: account_id=" << unsigned(account.id)
                  << " tx_hash=" << epee::string_tools::pod_to_hex(tx_entry.tx_hash)
                  << " output_index=" << index
                  << " amount=" << amount
                  << " daemon_receive_time=" << tx_entry.receive_time
                  << " lws_overlay_timestamp=" << overlay_timestamp
                  << " timestamp_delta_seconds=" << (overlay_timestamp >= tx_entry.receive_time ? overlay_timestamp - tx_entry.receive_time : 0)
                  << " fallback_used=" << (tx_entry.receive_time == 0));
          }
          ++matched_outputs;
        }
      }

      if (debug)
      {
        MINFO("lws-txpool-overlay: account_id=" << unsigned(account.id)
              << " txpool_txs=" << txpool_transactions->size()
              << " inspected_outputs=" << inspected_outputs
              << " matched_outputs=" << matched_outputs);
      }
      return matches;
    }

    void log_unspent_output_debug(const std::size_t response_index, const db::output& output, const bool debug)
    {
      if (!debug)
        return;

      MINFO("/get_unspent_outs output[" << response_index << "]: tx_hash="
            << epee::string_tools::pod_to_hex(output.link.tx_hash)
            << " global_index=" << output.spend_meta.id.low
            << " amount_bucket=" << output.spend_meta.id.high
            << " index=" << output.spend_meta.index
            << " amount=" << output.spend_meta.amount
            << " rct=" << is_ringct_output(output));
    }

    expect<epee::byte_slice> raw_json_response(const std::string& source)
    {
      epee::byte_stream out{};
      out.write(source.data(), source.size());
      return epee::byte_slice{std::move(out)};
    }

    bool should_passthrough_submit_raw_tx_error(const std::string& daemon_raw_response, const bool debug) noexcept
    {
      if (!debug)
        return false;

      return daemon_raw_response.find("double spend") != std::string::npos ||
        daemon_raw_response.find("double_spend") != std::string::npos ||
        daemon_raw_response.find("Double spend") != std::string::npos ||
        daemon_raw_response.find("DOUBLE_SPEND") != std::string::npos ||
        daemon_raw_response.find("invalid input") != std::string::npos ||
        daemon_raw_response.find("invalid_input") != std::string::npos ||
        daemon_raw_response.find("Invalid input") != std::string::npos ||
        daemon_raw_response.find("INVALID_INPUT") != std::string::npos;
    }

    bool is_locked(std::uint64_t unlock_time, db::block_id last, db::block_id tx_height) noexcept
    {
      if (unlock_time > CRYPTONOTE_MAX_BLOCK_NUMBER)
        return std::chrono::seconds{unlock_time} > std::chrono::system_clock::now().time_since_epoch() + std::chrono::seconds{CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2};
      if (unlock_time > to_uint(last) - 1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS)
        return true;
      return to_uint(tx_height) + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > to_uint(last);
    }

    bool is_hidden(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:
      case db::account_status::inactive:
        return false;
      default:
      case db::account_status::hidden:
        break;
      }
      return true;
    }

    bool key_check(const rpc::account_credentials& creds)
    {
      crypto::public_key verify{};
      if (!crypto::secret_key_to_public_key(creds.key, verify))
        return false;
      if (verify != creds.address.view_public)
        return false;
      return true;
    }

    expect<std::uint64_t> decode_registered_multisig_amount(
      const rpc::client& client,
      const db::account_address& address,
      const crypto::hash& tx_hash,
      const crypto::secret_key& tx_secret_key
    )
    {
      using get_transactions_rpc = cryptonote::rpc::GetTransactions;

      auto rpc_client = client.clone();
      if (!rpc_client)
        return rpc_client.error();

      get_transactions_rpc::Request tx_req{};
      tx_req.tx_hashes.push_back(tx_hash);

      MONERO_CHECK(rpc_client->send(
        rpc::client::make_message("get_transactions", tx_req),
        std::chrono::seconds{10}
      ));

      auto tx_raw = rpc_client->get_message(std::chrono::seconds{15});
      if (!tx_raw)
        return tx_raw.error();

      get_transactions_rpc::Response tx_resp{};
      MONERO_CHECK(rpc::parse_response(tx_resp, std::move(*tx_raw)));

      if (std::find(tx_resp.missed_hashes.begin(), tx_resp.missed_hashes.end(), tx_hash) != tx_resp.missed_hashes.end())
        return {lws::error::bad_daemon_response};

      const auto tx_it = tx_resp.txs.find(tx_hash);
      if (tx_it == tx_resp.txs.end())
        return {lws::error::bad_daemon_response};

      const cryptonote::transaction& tx = tx_it->second.transaction;

      cryptonote::tx_extra_pub_key tx_pub_key{};
      cryptonote::tx_extra_additional_pub_keys additional_tx_pub_keys{};
      {
        std::vector<cryptonote::tx_extra_field> extra{};
        cryptonote::parse_tx_extra(tx.extra, extra);
        if (!cryptonote::find_tx_extra_field_by_type(extra, tx_pub_key))
          return {lws::error::bad_daemon_response};
        cryptonote::find_tx_extra_field_by_type(extra, additional_tx_pub_keys);
      }

      // Derivation must use the RECIPIENT's view public key, not the tx pub key.
      // This matches wallet2::check_tx_key (L12330):
      //   generate_key_derivation(address.m_view_public_key, tx_key, derivation)
      // The shared secret is D = view_public * tx_secret = V * r
      crypto::key_derivation base_derivation{};
      if (!crypto::generate_key_derivation(address.view_public, tx_secret_key, base_derivation))
        return {lws::error::crypto_failure};

      // Note: additional_derivations require additional tx secret keys (one per output),
      // which the API does not currently provide. For standard (non-subaddress) multisig
      // addresses, the base_derivation alone is sufficient. If subaddress multisig support
      // is needed in the future, the API must be extended to accept additional_tx_keys.
      std::vector<crypto::key_derivation> additional_derivations{};

      std::uint64_t decoded_total = 0;
      bool matched_output = false;
      for (std::size_t index = 0; index < tx.vout.size(); ++index)
      {
        crypto::public_key out_pub_key{};
        if (!cryptonote::get_output_public_key(tx.vout[index], out_pub_key))
          continue;

        std::array<std::reference_wrapper<const crypto::key_derivation>, 2> candidates{{
          std::cref(base_derivation),
          std::cref(base_derivation)
        }};
        std::size_t candidate_count = 1;
        if (!additional_derivations.empty())
        {
          candidates[1] = std::cref(additional_derivations[index]);
          candidate_count = 2;
        }

        for (std::size_t candidate = 0; candidate < candidate_count; ++candidate)
        {
          const crypto::key_derivation& active_derivation = candidates[candidate].get();
          crypto::public_key expected_out_pub{};
          if (!crypto::derive_public_key(active_derivation, index, address.spend_public, expected_out_pub))
            return {lws::error::crypto_failure};

          if (expected_out_pub != out_pub_key)
            continue;

          matched_output = true;
          std::uint64_t amount = tx.vout[index].amount;
          if (!amount && 1 < tx.version)
          {
            if (tx.rct_signatures.outPk.size() <= index || tx.rct_signatures.ecdhInfo.size() <= index)
              return {lws::error::bad_daemon_response};

            const bool bulletproof2 = (rct::RCTTypeBulletproof2 <= tx.rct_signatures.type);
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk[index].mask,
              tx.rct_signatures.ecdhInfo[index],
              active_derivation,
              index,
              bulletproof2
            );
            if (!decrypted)
              return {lws::error::bad_daemon_response};
            amount = decrypted->first;
          }

          if (std::numeric_limits<std::uint64_t>::max() - decoded_total < amount)
            return {lws::error::bad_daemon_response};
          decoded_total += amount;
          break;
        }
      }

      if (!matched_output)
        return {lws::error::not_enough_amount};
      return decoded_total;
    }

    //! \return Account info from the DB, iff key matches address AND address is NOT hidden.
    expect<std::pair<db::account, db::storage_reader>> open_account(const rpc::account_credentials& creds, db::storage disk)
    {
      if (!key_check(creds))
        return {lws::error::bad_view_key};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();

      const auto user = reader->get_account(creds.address);
      if (!user)
        return user.error();
      if (is_hidden(user->first))
        return {lws::error::account_not_found};
      return {std::make_pair(user->second, std::move(*reader))};
    }

    bool check_lookahead(connection_data& data, const db::address_index lookahead)
    {
      const auto minor = to_uint(lookahead.min_i);
      if (minor)
      {
        const auto major = to_uint(lookahead.maj_i);
        if (std::numeric_limits<std::uint32_t>::max() < major / minor)
          return false;
        return major * minor <= data.global->options.max_subaddresses;
      }
      return true;
    }

    //! For endpoints that _sometimes_ generate async responses
    expect<epee::byte_slice> async_ready() noexcept
    { return epee::byte_slice{}; }

    //! Helper for `call` function when handling an _always_ async endpoint
    expect<epee::byte_slice> json_response(const expect<void>&) noexcept
    { return epee::byte_slice{}; }

    //! Helper for `call` function when handling a _sometimes_ async endpoint
    expect<epee::byte_slice> json_response(expect<epee::byte_slice> source) noexcept
    { return source; }

    //! Immediately generate JSON from `source`
    template<typename T>
    expect<epee::byte_slice> json_response(const T& source)
    {
      std::error_code error{};
      epee::byte_slice out{};
      if ((error = wire::json::to_bytes(out, source)))
        return error;
      return {std::move(out)};
    }

    //! Helper for `call` function when handling a _never_ async endpoint
    template<typename T>
    expect<epee::byte_slice> json_response(const expect<T>& source)
    { return json_response(source.value()); }

    std::atomic_flag rates_error_once = ATOMIC_FLAG_INIT;

    struct daemon_status
    {
      using request = rpc::daemon_status_request;
      using response = epee::byte_slice; // sometimes async
      using async_response = rpc::daemon_status_response;

      static expect<response> handle(request, const connection_data& data, std::function<async_complete>&& resume)
      {
        using info_rpc = cryptonote::rpc::GetInfo;

        struct frame
        {
          rest_server_data* parent;
          epee::byte_slice out;
          std::string in;
          net::zmq::async_client client;
          boost::asio::steady_timer timer;
          boost::asio::io_context::strand strand;
          std::vector<std::function<async_complete>> resumers;

          frame(rest_server_data& parent, net::zmq::async_client client)
            : parent(std::addressof(parent)),
              out(),
              in(),
              client(std::move(client)),
              timer(parent.io),
              strand(parent.io),
              resumers()
          {
            info_rpc::Request daemon_req{};
            out = rpc::client::make_message("get_info", daemon_req);
          }
        };

        struct cached_result
        {
          std::weak_ptr<frame> status;
          epee::byte_slice result;
          std::chrono::steady_clock::time_point last;
          boost::mutex sync;

          cached_result() noexcept
            : status(), result(), last(std::chrono::seconds{0}), sync()
          {}
        };

        static cached_result cache;
        boost::unique_lock<boost::mutex> lock{cache.sync};

        if (!cache.result.empty() && std::chrono::steady_clock::now() - cache.last < daemon_cache_timeout)
          return cache.result.clone();

        auto active = cache.status.lock();
        if (active)
        {
          active->resumers.push_back(std::move(resume));
          return async_ready();
        }

        struct async_handler : public boost::asio::coroutine
        {
          std::shared_ptr<frame> self_;

          explicit async_handler(std::shared_ptr<frame> self)
            : boost::asio::coroutine(), self_(std::move(self))
          {}

          void send_response(const boost::system::error_code error, const expect<copyable_slice>& value)
          {
            assert(self_ != nullptr);
            assert(self_->strand.running_in_this_thread());

            if (error)
              MERROR("Failure in /daemon_status: " << error.message());
            else
            {
              // only re-use REQ socket if in proper state
              MDEBUG("Completed ZMQ request in /daemon_status");
              self_->parent->store_async_client(std::move(self_->client));
            }

            std::vector<std::function<async_complete>> resumers;
            {
              const boost::lock_guard<boost::mutex> lock{cache.sync};
              cache.status.reset(); // prevent more resumers being added
              resumers.swap(self_->resumers);
              if (value)
              {
                cache.result = value->value.clone();
                cache.last = std::chrono::steady_clock::now();
              }
              else
                cache.result = nullptr; // serialization error
            }

            // send default constructed response if I/O `error`
            for (const auto& r : resumers)
              r(value);
          }

          bool set_timeout(std::chrono::steady_clock::duration timeout, const bool expecting) const
          {
            struct on_timeout
            {
              std::shared_ptr<frame> self_;

              void operator()(const boost::system::error_code error) const
              {
                if (!self_ || error == boost::asio::error::operation_aborted)
                  return;

                assert(self_->strand.running_in_this_thread());
                MWARNING("Timeout on /daemon_status ZMQ call");
                self_->client.close = true;
                self_->client.asock->cancel();
              }
            };

            assert(self_ != nullptr);
            if (!self_->timer.expires_after(timeout) && expecting)
              return false;

            self_->timer.async_wait(boost::asio::bind_executor(self_->strand, on_timeout{self_}));
            return true;
          }

          void operator()(boost::system::error_code error = {}, const std::size_t bytes = 0)
          {
            if (!self_)
              return;
            if (error)
              return send_response(error, json_response(async_response{}));

            frame& self = *self_;
            assert(self.strand.running_in_this_thread());
            BOOST_ASIO_CORO_REENTER(*this)
            {
              set_timeout(std::chrono::seconds{2}, false);
              BOOST_ASIO_CORO_YIELD net::zmq::async_write(
                self.client, std::move(self.out), boost::asio::bind_executor(self.strand, std::move(*this))
              );

              if (!set_timeout(std::chrono::seconds{5}, true))
                return send_response(boost::asio::error::operation_aborted, json_response(async_response{}));

              BOOST_ASIO_CORO_YIELD net::zmq::async_read(
                self.client, self.in, boost::asio::bind_executor(self.strand, std::move(*this))
              );

              if (!self.timer.cancel())
                return send_response(boost::asio::error::operation_aborted, json_response(async_response{}));

              {
                info_rpc::Response daemon_resp{};
                const expect<void> status =
                  rpc::parse_response(daemon_resp, std::move(self.in));
                if (!status)
                  return send_response({}, status.error());

                async_response resp{};

                resp.outgoing_connections_count = daemon_resp.info.outgoing_connections_count;
                resp.incoming_connections_count = daemon_resp.info.incoming_connections_count;
                resp.height = daemon_resp.info.height;
                resp.target_height = daemon_resp.info.target_height;

                if (!resp.outgoing_connections_count && !resp.incoming_connections_count)
                  resp.state = rpc::daemon_state::no_connections;
                else if (resp.target_height && (resp.target_height - resp.height) >= 5)
                  resp.state = rpc::daemon_state::synchronizing;
                else
                  resp.state = rpc::daemon_state::ok;

                send_response({}, json_response(std::move(resp)));
              }
            }
          }
        };

        expect<net::zmq::async_client> client = data.global->get_async_client();
        if (!client)
          return client.error();

        active = std::make_shared<frame>(*data.global, std::move(*client));
        cache.result = nullptr;
        cache.status = active;
        active->resumers.push_back(std::move(resume));
        lock.unlock();

        MDEBUG("Starting new ZMQ request in /daemon_status");
        boost::asio::dispatch(active->strand, async_handler{active});
        return async_ready();
      }
    };

    struct get_address_info
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_info_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        auto user = open_account(req, data.global->disk.clone());
        if (!user)
          return user.error();

        data.passed_login = true;
        response resp{};

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        auto confirmed = user->second.get_confirmed_spend_images(user->first.id);
        if (!confirmed)
          return confirmed.error();

        auto imported_sources = user->second.get_imported_spend_sources(user->first.id);
        if (!imported_sources)
          return imported_sources.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        auto txpool_overlay = fetch_txpool_incoming_overlay(user->first, data.global->client, data.global->options.debug);
        if (!txpool_overlay)
        {
          MWARNING("/get_address_info txpool overlay unavailable: " << txpool_overlay.error().message());
          txpool_overlay = std::vector<txpool_overlay_match>{};
        }

        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.lookahead_fail = to_uint(user->first.lookahead_fail);
        resp.lookahead = user->first.lookahead;

        std::vector<db::output> output_rows{};
        output_rows.reserve(outputs->count());

        for (auto output = outputs->make_iterator(); !output.is_end(); ++output)
        {
          const db::output out = *output;
          const db::output::spend_meta_ meta = out.spend_meta;

          output_rows.push_back(out);

          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + meta.amount);
          if (is_locked(out.unlock_time, last->id, out.link.height))
            resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + meta.amount);
        }

        std::size_t txpool_overlay_added = 0;
        std::uint64_t txpool_overlay_amount = 0;
        for (const txpool_overlay_match& match : *txpool_overlay)
        {
          if (output_exists_in_rows(output_rows, match))
            continue;
          output_rows.push_back(match.output);
          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + match.output.spend_meta.amount);
          resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + match.output.spend_meta.amount);
          if (std::numeric_limits<std::uint64_t>::max() - txpool_overlay_amount < match.output.spend_meta.amount)
            return {lws::error::bad_daemon_response};
          txpool_overlay_amount += match.output.spend_meta.amount;
          ++txpool_overlay_added;
        }

        std::set<crypto::key_image, key_image_less> confirmed_images{};
        for (const auto& image : confirmed->make_range())
          confirmed_images.insert(image);

        std::map<crypto::key_image, db::key_image_source, key_image_less> imported_source_map{};
        for (const auto& source : imported_sources->make_range())
          imported_source_map.emplace(source.image, source);

        std::uint64_t total_sent = 0;
        std::size_t confirmed_spend_count = 0;
        std::size_t unconfirmed_spend_count = 0;
        std::size_t missing_source_count = 0;
        std::size_t imported_source_candidate_count = 0;
        std::size_t unconfirmed_spend_samples = 0;
        std::map<crypto::key_image, confirmed_spend_choice, key_image_less> confirmed_spend_choices{};
        for (const auto& spend : spends->make_range())
        {
          if (confirmed_images.count(spend.image) == 0)
          {
            ++unconfirmed_spend_count;
            if (data.global->options.debug && unconfirmed_spend_samples < 8)
            {
              MINFO("/get_address_info unconfirmed spend sample[" << unconfirmed_spend_samples << "]: key_image="
                    << epee::string_tools::pod_to_hex(spend.image)
                    << " source_global_index=" << spend.source.low
                    << " source_amount_bucket=" << spend.source.high
                    << " spend_tx_hash=" << epee::string_tools::pod_to_hex(spend.link.tx_hash)
                    << " spend_height=" << db::to_uint(spend.link.height)
                    << " mixin_count=" << spend.mixin_count);
              ++unconfirmed_spend_samples;
            }
            continue;
          }
          else
            ++confirmed_spend_count;

          const auto* output = find_output_by_imported_source(output_rows, imported_source_map, spend.image);
          const bool imported_source = output != nullptr;
          if (!output)
            output = find_output_by_id(output_rows, spend.source);
          if (!output)
          {
            ++missing_source_count;
            continue;
          }
          if (imported_source)
            ++imported_source_candidate_count;

          confirmed_spend_choice choice{spend, output->spend_meta, output->spend_meta.id, imported_source};
          const auto existing = confirmed_spend_choices.find(spend.image);
          if (existing == confirmed_spend_choices.end())
            confirmed_spend_choices.emplace(spend.image, std::move(choice));
          else if (should_replace_confirmed_spend_choice(existing->second, choice))
            existing->second = std::move(choice);
        }

        std::set<db::output_id, output_id_less> total_sent_sources{};
        std::size_t imported_source_count = 0;
        for (const auto& choice_entry : confirmed_spend_choices)
        {
          const confirmed_spend_choice& choice = choice_entry.second;
          if (!total_sent_sources.insert(choice.source).second)
            continue;
          if (choice.imported_source)
            ++imported_source_count;
          if (std::numeric_limits<std::uint64_t>::max() - total_sent < choice.meta.amount)
            return {lws::error::bad_daemon_response};
          total_sent += choice.meta.amount;
          resp.spent_outputs.push_back(rpc::transaction_spend{choice.meta, choice.spend});
        }
        resp.total_sent = rpc::safe_uint64(total_sent);

        if (data.global->options.debug)
        {
          MINFO("/get_address_info balance summary: outputs=" << outputs->count()
                << " patch_marker=" << lws_spent_state_patch_marker
                << " balance_policy=confirmed_spend_sources_only"
                << " unspent_policy=not_applicable"
                << " spends=" << spends->count()
                << " confirmed_spend_images=" << confirmed_images.size()
                << " confirmed_spends=" << confirmed_spend_count
                << " confirmed_spend_selected=" << confirmed_spend_choices.size()
                << " unique_confirmed_sources=" << total_sent_sources.size()
                << " imported_exact_sources=" << imported_source_count
                << " imported_exact_source_candidates=" << imported_source_candidate_count
                << " unconfirmed_spends=" << unconfirmed_spend_count
                << " missing_source_spends=" << missing_source_count
                << " total_received=" << std::uint64_t(resp.total_received)
                << " total_sent=" << std::uint64_t(resp.total_sent)
                << " locked_funds=" << std::uint64_t(resp.locked_funds)
                << " txpool_overlay_added=" << txpool_overlay_added
                << " txpool_overlay_amount=" << txpool_overlay_amount
                << " spent_outputs=" << resp.spent_outputs.size()
                << " scan_height=" << std::uint64_t(user->first.scan_height)
                << " blockchain_height=" << resp.blockchain_height);
        }

        // `get_rates()` nevers does I/O, so handler can remain synchronous
        resp.rates = data.global->client.get_rates();
        if (!resp.rates && !rates_error_once.test_and_set(std::memory_order_relaxed))
          MWARNING("Unable to retrieve exchange rates: " << resp.rates.error().message());

        return resp;
      }
    };

    struct get_address_txs
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_txs_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        auto user = open_account(req, data.global->disk.clone());
        if (!user)
          return user.error();

        data.passed_login = true;
        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        auto confirmed = user->second.get_confirmed_spend_images(user->first.id);
        if (!confirmed)
          return confirmed.error();

        auto imported_sources = user->second.get_imported_spend_sources(user->first.id);
        if (!imported_sources)
          return imported_sources.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        auto txpool_overlay = fetch_txpool_incoming_overlay(user->first, data.global->client, data.global->options.debug);
        if (!txpool_overlay)
        {
          MWARNING("/get_address_txs txpool overlay unavailable: " << txpool_overlay.error().message());
          txpool_overlay = std::vector<txpool_overlay_match>{};
        }

        response resp{};
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;
        resp.lookahead_fail = to_uint(user->first.lookahead_fail);
        resp.lookahead = user->first.lookahead;

        auto output = outputs->make_iterator();
        std::vector<std::pair<db::output_id, std::size_t>> output_to_tx{};
        output_to_tx.reserve(outputs->count());
        std::vector<db::output> output_rows{};
        output_rows.reserve(outputs->count());

        resp.transactions.reserve(outputs->count());
        db::transaction_link next_output{};

        if (!output.is_end())
          next_output = output.get_value<MONERO_FIELD(db::output, link)>();

        while (!output.is_end())
        {
          if (!resp.transactions.empty())
          {
            db::transaction_link const& last = resp.transactions.back().info.link;

            if (next_output < last)
            {
              throw std::logic_error{"DB has unexpected sort order"};
            }
          }

          std::uint64_t amount = 0;
          if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_output.tx_hash)
          {
            resp.transactions.push_back({*output});
            amount = resp.transactions.back().info.spend_meta.amount;
          }
          else
          {
            amount = output.get_value<MONERO_FIELD(db::output, spend_meta.amount)>();
            resp.transactions.back().info.spend_meta.amount += amount;
          }

          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + amount);

          output_rows.push_back(*output);
          const auto meta = output.get_value<MONERO_FIELD(db::output, spend_meta)>();
          output_to_tx.push_back({meta.id, resp.transactions.size() - 1});

          ++output;
          if (!output.is_end())
            next_output = output.get_value<MONERO_FIELD(db::output, link)>();
        }

        std::size_t txs_txpool_overlay_added = 0;
        std::uint64_t txs_txpool_overlay_amount = 0;
        for (const txpool_overlay_match& match : *txpool_overlay)
        {
          if (output_exists_in_rows(output_rows, match))
            continue;
          resp.transactions.push_back({match.output, {}, 0});
          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + match.output.spend_meta.amount);
          output_rows.push_back(match.output);
          output_to_tx.push_back({match.output.spend_meta.id, resp.transactions.size() - 1});
          if (std::numeric_limits<std::uint64_t>::max() - txs_txpool_overlay_amount < match.output.spend_meta.amount)
            return {lws::error::bad_daemon_response};
          txs_txpool_overlay_amount += match.output.spend_meta.amount;
          ++txs_txpool_overlay_added;
        }

        std::set<crypto::key_image, key_image_less> confirmed_images{};
        for (const auto& image : confirmed->make_range())
          confirmed_images.insert(image);

        std::map<crypto::key_image, db::key_image_source, key_image_less> imported_source_map{};
        for (const auto& source : imported_sources->make_range())
          imported_source_map.emplace(source.image, source);

        auto find_tx_index = [&resp] (const crypto::hash& tx_hash) -> boost::optional<std::size_t>
        {
          for (std::size_t index = 0; index < resp.transactions.size(); ++index)
          {
            if (resp.transactions[index].info.link.tx_hash == tx_hash)
              return index;
          }
          return boost::none;
        };

        std::uint64_t txs_total_sent = 0;
        std::size_t txs_confirmed_spend_count = 0;
        std::size_t txs_unconfirmed_spend_count = 0;
        std::size_t txs_missing_source_count = 0;
        std::size_t txs_outgoing_only_count = 0;
        std::size_t txs_imported_source_candidate_count = 0;
        std::size_t txs_unconfirmed_spend_samples = 0;
        std::map<crypto::key_image, confirmed_spend_choice, key_image_less> txs_confirmed_spend_choices{};
        for (const auto& spend : spends->make_range())
        {
          if (confirmed_images.count(spend.image) == 0)
          {
            ++txs_unconfirmed_spend_count;
            if (data.global->options.debug && txs_unconfirmed_spend_samples < 8)
            {
              MINFO("/get_address_txs unconfirmed spend sample[" << txs_unconfirmed_spend_samples << "]: key_image="
                    << epee::string_tools::pod_to_hex(spend.image)
                    << " source_global_index=" << spend.source.low
                    << " source_amount_bucket=" << spend.source.high
                    << " spend_tx_hash=" << epee::string_tools::pod_to_hex(spend.link.tx_hash)
                    << " spend_height=" << db::to_uint(spend.link.height)
                    << " mixin_count=" << spend.mixin_count);
              ++txs_unconfirmed_spend_samples;
            }
            continue;
          }
          else
            ++txs_confirmed_spend_count;

          const auto* output = find_output_by_imported_source(output_rows, imported_source_map, spend.image);
          const bool imported_source = output != nullptr;
          if (!output)
            output = find_output_by_id(output_rows, spend.source);
          if (!output)
          {
            ++txs_missing_source_count;
            continue;
          }
          if (imported_source)
            ++txs_imported_source_candidate_count;

          confirmed_spend_choice choice{spend, output->spend_meta, output->spend_meta.id, imported_source};
          const auto existing = txs_confirmed_spend_choices.find(spend.image);
          if (existing == txs_confirmed_spend_choices.end())
            txs_confirmed_spend_choices.emplace(spend.image, std::move(choice));
          else if (should_replace_confirmed_spend_choice(existing->second, choice))
            existing->second = std::move(choice);
        }

        std::set<db::output_id, output_id_less> txs_total_sent_sources{};
        std::size_t txs_imported_source_count = 0;
        for (const auto& choice_entry : txs_confirmed_spend_choices)
        {
          const confirmed_spend_choice& choice = choice_entry.second;
          if (!txs_total_sent_sources.insert(choice.source).second)
            continue;
          if (choice.imported_source)
            ++txs_imported_source_count;
          auto tx_index = find_tx_index(choice.spend.link.tx_hash);
          if (!tx_index)
          {
            db::output outgoing{};
            outgoing.link = choice.spend.link;
            outgoing.spend_meta = choice.meta;
            outgoing.spend_meta.amount = 0;
            outgoing.spend_meta.mixin_count = choice.spend.mixin_count;
            outgoing.timestamp = choice.spend.timestamp;
            outgoing.unlock_time = choice.spend.unlock_time;
            outgoing.extra = db::pack(static_cast<db::extra>(0), choice.spend.length);
            outgoing.payment_id.long_ = choice.spend.payment_id;
            outgoing.fee = 0;
            outgoing.recipient = choice.spend.sender;

            resp.transactions.push_back({std::move(outgoing), {}, 0});
            tx_index = resp.transactions.size() - 1;
            ++txs_outgoing_only_count;
          }

          auto& tx = resp.transactions.at(*tx_index);
          if (std::numeric_limits<std::uint64_t>::max() - tx.spent < choice.meta.amount)
            return {lws::error::bad_daemon_response};
          tx.spent += choice.meta.amount;
          if (std::numeric_limits<std::uint64_t>::max() - txs_total_sent < choice.meta.amount)
            return {lws::error::bad_daemon_response};
          txs_total_sent += choice.meta.amount;
          tx.spends.push_back(rpc::transaction_spend{choice.meta, choice.spend});
        }

        if (data.global->options.debug)
        {
          MINFO("/get_address_txs summary: outputs=" << outputs->count()
                << " patch_marker=" << lws_spent_state_patch_marker
                << " balance_policy=confirmed_spend_sources_only"
                << " unspent_policy=not_applicable"
                << " spends=" << spends->count()
                << " confirmed_spend_images=" << confirmed_images.size()
                << " confirmed_spends=" << txs_confirmed_spend_count
                << " confirmed_spend_selected=" << txs_confirmed_spend_choices.size()
                << " unique_confirmed_sources=" << txs_total_sent_sources.size()
                << " imported_exact_sources=" << txs_imported_source_count
                << " imported_exact_source_candidates=" << txs_imported_source_candidate_count
                << " unconfirmed_spends=" << txs_unconfirmed_spend_count
                << " missing_source_spends=" << txs_missing_source_count
                << " outgoing_only_txs=" << txs_outgoing_only_count
                << " transactions_before_sort=" << resp.transactions.size()
                << " total_received=" << std::uint64_t(resp.total_received)
                << " total_sent_from_candidate_spends=" << txs_total_sent
                << " txpool_overlay_added=" << txs_txpool_overlay_added
                << " txpool_overlay_amount=" << txs_txpool_overlay_amount
                << " scan_height=" << resp.scanned_height
                << " blockchain_height=" << resp.blockchain_height);
        }

        std::sort(
          resp.transactions.begin(),
          resp.transactions.end(),
          [] (const rpc::get_address_txs_response::transaction& left,
              const rpc::get_address_txs_response::transaction& right)
          {
            return left.info.link < right.info.link;
          }
        );

        return resp;
      }
    };

    struct get_random_outs
    {
      using request = rpc::get_random_outs_request;
      using response = void; // always asynchronous response
      using async_response = rpc::get_random_outs_response;

      static expect<response> handle(request req, const connection_data& data,  std::function<async_complete>&& resume)
      {
        using distribution_rpc = cryptonote::rpc::GetOutputDistribution;
        using histogram_rpc = cryptonote::rpc::GetOutputHistogram;
        using distribution_rpc = cryptonote::rpc::GetOutputDistribution;

        if (max_ring_size < req.count || max_rings < req.amounts.values.size())
          return {lws::error::exceeded_rest_request_limit};

        std::sort(req.amounts.values.begin(), req.amounts.values.end(), std::greater<>{});

        struct frame
        {
          rest_server_data* parent;
          net::zmq::async_client client;
          boost::asio::steady_timer timer;
          boost::asio::strand<boost::asio::io_context::executor_type> strand;
          std::deque<std::pair<request, std::function<async_complete>>> resumers;

          frame(rest_server_data& parent, net::zmq::async_client client)
            : parent(std::addressof(parent)),
              client(std::move(client)),
              timer(parent.io),
              strand(parent.io.get_executor()),
              resumers()
          {}
        };

        struct cached_result
        {
          std::weak_ptr<frame> status;
          boost::mutex sync;

          cached_result() noexcept
            : status(), sync()
          {}
        };

        static cached_result cache;
        boost::unique_lock<boost::mutex> lock{cache.sync};

        auto active = cache.status.lock();
        if (active)
        {
          active->resumers.emplace_back(std::move(req), std::move(resume));
          return success();
        }

        struct async_handler
        {
          std::shared_ptr<frame> self_;

          explicit async_handler(std::shared_ptr<frame> self)
            : self_(std::move(self))
          {}

          void send_response(const boost::system::error_code error, expect<copyable_slice> value) const
          {
            assert(self_ != nullptr);

            std::deque<std::pair<request, std::function<async_complete>>> resumers;
            {
              const boost::lock_guard<boost::mutex> lock{cache.sync};
              if (error)
              {
                // Prevent further resumers, ZMQ REQ/REP in bad state
                MERROR("Failure in /get_random_outs: " << error.message());
                if (value)
                  value = {lws::error::daemon_timeout};
                cache.status.reset();
                resumers.swap(self_->resumers);
              }
              else
              {
                MDEBUG("Completed ZMQ request in /get_random_outs");
                resumers.push_back(std::move(self_->resumers.front()));
                self_->resumers.pop_front();
              }
            }

            for (const auto& r : resumers)
              r.second(value);
          }

          bool set_timeout(std::chrono::steady_clock::duration timeout, const bool expecting) const
          {
            assert(self_ != nullptr);
            if (!self_->timer.expires_after(timeout) && expecting)
              return false;

            auto& self = self_;
            self->timer.async_wait(
              [self] (boost::system::error_code error)
              {
                if (error == boost::asio::error::operation_aborted)
                  return;

                boost::asio::dispatch(
                  self->strand,
                  [self] ()
                  {
                    boost::system::error_code error{};
                    MWARNING("Timeout on /get_random_outs ZMQ call");
                    self->client.close = true;
                    self->client.asock->cancel(error);
                  }
                );
              }
            );
            return true;
          }

          void operator()(boost::asio::yield_context yield) const
          {
            if (!self_)
              return;

            std::chrono::steady_clock::time_point last{std::chrono::seconds{0}};
            std::vector<std::uint64_t> distributions{};
            request next{};

            for (;;)
            {
              {
                const boost::lock_guard<boost::mutex> lock{cache.sync};
                if (self_->resumers.empty())
                {
                  cache.status.reset();
                  self_->parent->store_async_client(std::move(self_->client));
                  MDEBUG("Finishing ZMQ coroutine in /get_random_outs");
                  return;
                }
                next = std::move(self_->resumers.front().first);
              }

              boost::system::error_code error{};
              std::vector<lws::histogram> histograms{};
              const std::size_t ringct_count =
                next.amounts.values.end() -
                  std::lower_bound(
                    next.amounts.values.begin(), next.amounts.values.end(), 0, std::greater<>{}
                  );

              if (ringct_count < next.amounts.values.size())
              {
                // reuse allocated vector memory
                next.amounts.values.resize(next.amounts.values.size() - ringct_count);

                histogram_rpc::Request histogram_req{};
                histogram_req.amounts = std::move(next.amounts.values);
                histogram_req.min_count = 0;
                histogram_req.max_count = 0;
                histogram_req.unlocked = true;
                histogram_req.recent_cutoff = 0;

                epee::byte_slice msg = rpc::client::make_message("get_output_histogram", histogram_req);

                MDEBUG("Fetching histograms for /get_random_outs");
                set_timeout(std::chrono::seconds{10}, false);
                net::zmq::async_write(self_->client, std::move(msg), yield[error]);
                if (error)
                  return send_response(error, async_ready());
                if (!set_timeout(std::chrono::minutes{3}, true))
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                std::string in;
                net::zmq::async_read(self_->client, in, yield[error]);
                if (error)
                  return send_response(error, async_ready());
                if (!self_->timer.cancel())
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                histogram_rpc::Response histogram_resp{};
                const expect<void> status =
                  rpc::parse_response(histogram_resp, std::move(in));
                if (!status)
                  return send_response(boost::asio::error::invalid_argument, status.error());
                if (histogram_resp.histogram.size() != histogram_req.amounts.size())
                  return send_response(boost::asio::error::invalid_argument, {lws::error::bad_daemon_response});

                histograms = std::move(histogram_resp.histogram);

                next.amounts.values = std::move(histogram_req.amounts);
                next.amounts.values.insert(next.amounts.values.end(), ringct_count, 0);
              }

              if (ringct_count && (distributions.empty() || (daemon_cache_timeout < std::chrono::steady_clock::now() - last)))
              {
                distribution_rpc::Request distribution_req{};
                if (ringct_count == next.amounts.values.size())
                {
                  distribution_req.amounts = std::move(next.amounts.values);
                  next.amounts.values.clear();
                }

                distribution_req.amounts.resize(1);
                distribution_req.from_height = 0;
                distribution_req.to_height = 0;
                distribution_req.cumulative = true;

                epee::byte_slice msg =
                  rpc::client::make_message("get_output_distribution", distribution_req);

                MDEBUG("Fetching distributions for /get_random_outs");
                set_timeout(std::chrono::seconds{10}, false);
                net::zmq::async_write(self_->client, std::move(msg), yield[error]);
                if (error)
                  return send_response(error, async_ready());
                if (!set_timeout(std::chrono::minutes{3}, true))
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                std::string in;
                net::zmq::async_read(self_->client, in, yield[error]);
                if (error)
                  return send_response(error, async_ready());
                if (!self_->timer.cancel())
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                distribution_rpc::Response distribution_resp{};
                const expect<void> status =
                  rpc::parse_response(distribution_resp, std::move(in));
                if (!status)
                  return send_response(boost::asio::error::invalid_argument, status.error());
                if (distribution_resp.distributions.size() != 1)
                  return send_response(boost::asio::error::invalid_argument, {lws::error::bad_daemon_response});
                if (distribution_resp.distributions[0].amount != 0)
                  return send_response(boost::asio::error::invalid_argument, {lws::error::bad_daemon_response});

                last = std::chrono::steady_clock::now();
                distributions = std::move(distribution_resp.distributions[0].data.distribution);

                if (next.amounts.values.empty())
                {
                  next.amounts.values = std::move(distribution_req.amounts);
                  next.amounts.values.insert(
                    next.amounts.values.end(), ringct_count - 1, 0
                  );
                }
              }

              class zmq_fetch_keys
              {
                async_handler self_;
                boost::asio::yield_context yield_;

              public:
                zmq_fetch_keys(async_handler self, boost::asio::yield_context yield)
                  : self_(std::move(self)), yield_(std::move(yield))
                {}

                zmq_fetch_keys(zmq_fetch_keys&&) = default;
                zmq_fetch_keys(const zmq_fetch_keys&) = default;

                expect<std::vector<output_keys>> operator()(std::vector<lws::output_ref> ids) const
                {
                  using get_keys_rpc = cryptonote::rpc::GetOutputKeys;
                  if (self_.self_ == nullptr)
                    throw std::logic_error{"Unexpected nullptr in zmq_fetch_keys"};

                  boost::system::error_code error{};
                  get_keys_rpc::Request keys_req{};
                  keys_req.outputs = std::move(ids);

                  epee::byte_slice msg = rpc::client::make_message("get_output_keys", keys_req);

                  self_.set_timeout(std::chrono::seconds{10}, false);
                  net::zmq::async_write(self_.self_->client, std::move(msg), yield_[error]);

                  if (error)
                  {
                    MERROR("Internal ZMQ error in /get_random_outs: " << error.message());
                    return {error::daemon_timeout};
                  }
                  if (!self_.set_timeout(std::chrono::seconds{10}, true))
                    return {error::daemon_timeout};

                  std::string in;
                  net::zmq::async_read(self_.self_->client, in, yield_[error]);
                  if (error)
                  {
                    MERROR("Internal ZMQ error in /get_random_outs: " << error.message());
                    return {error::daemon_timeout};
                  }
                  if (!self_.self_->timer.cancel())
                    return {error::daemon_timeout};

                  get_keys_rpc::Response keys_resp{};
                  const expect<void> status =
                    rpc::parse_response(keys_resp, std::move(in));
                  if (!status)
                    return status.error();

                  return {std::move(keys_resp.keys)};
                }
              };

              lws::gamma_picker pick_rct{std::move(distributions)};
              auto rings = pick_random_outputs(
                next.count,
                epee::to_span(next.amounts.values),
                pick_rct,
                epee::to_mut_span(histograms),
                zmq_fetch_keys{*this, yield}
              );
              distributions = pick_rct.take_offsets();
              if (!rings)
                return send_response(boost::asio::error::invalid_argument, rings.error());
              else
                send_response({}, json_response(async_response{std::move(*rings)}));
            }
          }
        };

        expect<net::zmq::async_client> client = data.global->get_async_client();
        if (!client)
          return client.error();

        active = std::make_shared<frame>(*data.global, std::move(*client));
        cache.status = active;

        active->resumers.emplace_back(std::move(req), std::move(resume));
        lock.unlock();

        MDEBUG("Starting new ZMQ coroutine in /get_random_outs");
#if BOOST_VERSION >= 108000
        {
          auto token = [] (const std::exception_ptr& e)
          {
            if (e)
              std::rethrow_exception(e);
          };
          boost::asio::spawn(active->strand, async_handler{active}, std::move(token));
        }
#else
        boost::asio::spawn(active->strand, async_handler{active});
#endif
        return success();
      }
    };

    struct get_subaddrs
    {
      using request = rpc::account_credentials;
      using response = rpc::get_subaddrs_response;

      static expect<response> handle(request const& req, connection_data& data, std::function<async_complete>&&)
      {
        auto user = open_account(req, data.global->disk.clone());
        if (!user)
          return user.error();

        data.passed_login = true;
        auto subaddrs = user->second.get_subaddresses(user->first.id);
        if (!subaddrs)
          return subaddrs.error();
        return response{std::move(*subaddrs)};
      }
    };

    struct get_unspent_outs
    {
      using request = rpc::get_unspent_outs_request;
      using response = epee::byte_slice; // somtimes async response
      using async_response = rpc::get_unspent_outs_response;
      using rpc_command = cryptonote::rpc::GetFeeEstimate;

      static expect<std::unordered_map<crypto::hash, std::vector<crypto::public_key>>> fetch_additional_tx_pub_keys(
        const std::vector<std::pair<db::output, std::vector<crypto::key_image>>>& unspent,
        const rpc::client& daemon_client)
      {
        std::set<crypto::hash, hash_less> tx_hashes_set{};
        for (const auto& output : unspent)
          tx_hashes_set.insert(output.first.link.tx_hash);

        std::vector<crypto::hash> tx_hashes{};
        tx_hashes.reserve(tx_hashes_set.size());
        tx_hashes.insert(tx_hashes.end(), tx_hashes_set.begin(), tx_hashes_set.end());

        if (tx_hashes.empty())
          return {std::unordered_map<crypto::hash, std::vector<crypto::public_key>>{}};

        auto rpc_client = daemon_client.clone();
        if (!rpc_client)
          return rpc_client.error();

        cryptonote::rpc::GetTransactions::Request tx_req{};
        tx_req.tx_hashes = tx_hashes;
        MONERO_CHECK(rpc_client->send(rpc::client::make_message("get_transactions", tx_req), std::chrono::seconds{10}));

        auto tx_raw = rpc_client->get_message(std::chrono::seconds{15});
        if (!tx_raw)
          return tx_raw.error();

        cryptonote::rpc::GetTransactions::Response tx_resp{};
        MONERO_CHECK(rpc::parse_response(tx_resp, std::move(*tx_raw)));

        if (!tx_resp.missed_hashes.empty())
          return {lws::error::bad_daemon_response};

        std::unordered_map<crypto::hash, std::vector<crypto::public_key>> out{};
        out.reserve(tx_hashes.size());
        for (const crypto::hash& tx_hash : tx_hashes)
        {
          const auto tx_it = tx_resp.txs.find(tx_hash);
          if (tx_it == tx_resp.txs.end())
            return {lws::error::bad_daemon_response};

          cryptonote::tx_extra_additional_pub_keys additional_tx_pub_keys{};
          std::vector<cryptonote::tx_extra_field> extra{};
          cryptonote::parse_tx_extra(tx_it->second.transaction.extra, extra);
          cryptonote::find_tx_extra_field_by_type(extra, additional_tx_pub_keys);

          out.emplace(tx_hash, std::move(additional_tx_pub_keys.data));
        }

        return out;
      }

      static expect<response> generate_response(
        request req,
        const expect<rpc_command::Response>& rpc,
        db::storage disk,
        const rpc::client& daemon_client,
        const bool debug)
      {
        if (!rpc)
          return rpc.error();

        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        if ((req.use_dust && *req.use_dust) || !req.dust_threshold)
          req.dust_threshold = rpc::safe_uint64(0);

        if (!req.mixin)
          req.mixin = 0;

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        auto confirmed = user->second.get_confirmed_spend_images(user->first.id);
        if (!confirmed)
          return confirmed.error();

        std::set<crypto::key_image, key_image_less> confirmed_images{};
        for (const auto& image : confirmed->make_range())
          confirmed_images.insert(image);

        std::set<db::output_id, output_id_less> confirmed_sources{};
        for (const auto& spend : spends->make_range())
        {
          if (confirmed_images.count(spend.image) == 0)
            continue;
          confirmed_sources.insert(spend.source);
        }

        auto pending_stream = user->second.get_pending_spends(user->first.id);
        if (!pending_stream)
          return pending_stream.error();

        const std::uint64_t now = unix_timestamp_now();
        std::size_t pending_loaded_count = 0;
        std::size_t pending_active_count = 0;
        std::size_t pending_expired_count = 0;
        std::vector<db::pending_spend> pending_active{};
        pending_active.reserve(pending_stream->count());
        for (const auto& pending : pending_stream->make_range())
        {
          ++pending_loaded_count;
          const std::uint64_t recorded = std::uint64_t(pending.recorded);
          if (recorded <= now && now - recorded <= pending_spend_ttl_seconds)
          {
            pending_active.push_back(pending);
            ++pending_active_count;
          }
          else
          {
            ++pending_expired_count;
          }
        }

        std::uint64_t received = 0;
        std::uint64_t candidate_spent_hidden_amount = 0;
        std::size_t candidate_spent_hidden_count = 0;
        std::uint64_t dust_or_mixin_skipped_amount = 0;
        std::size_t dust_or_mixin_skipped_count = 0;
        std::uint64_t confirmed_source_skipped_amount = 0;
        std::size_t confirmed_source_skipped_count = 0;
        std::uint64_t confirmed_image_skipped_amount = 0;
        std::size_t confirmed_image_skipped_count = 0;
        std::uint64_t pending_source_skipped_amount = 0;
        std::size_t pending_source_skipped_count = 0;
        std::uint64_t clean_returned_amount = 0;
        std::size_t clean_returned_count = 0;
        std::size_t candidate_spent_samples = 0;
        std::vector<std::pair<db::output, std::vector<crypto::key_image>>> unspent;

        unspent.reserve(outputs->count());
        for (db::output const& out : outputs->make_range())
        {
          if (out.spend_meta.amount < std::uint64_t(*req.dust_threshold) || out.spend_meta.mixin_count < *req.mixin)
          {
            ++dust_or_mixin_skipped_count;
            if (std::numeric_limits<std::uint64_t>::max() - dust_or_mixin_skipped_amount < out.spend_meta.amount)
              return {lws::error::bad_daemon_response};
            dust_or_mixin_skipped_amount += out.spend_meta.amount;
            continue;
          }

          auto spend_images = get_output_spend_images(user->second, out.spend_meta.id);
          if (!spend_images)
            return spend_images.error();

          const bool confirmed_image_match = has_confirmed_spend_image(*spend_images, confirmed_images);
          if (!spend_images->empty())
          {
            ++candidate_spent_hidden_count;
            if (std::numeric_limits<std::uint64_t>::max() - candidate_spent_hidden_amount < out.spend_meta.amount)
              return {lws::error::bad_daemon_response};
            candidate_spent_hidden_amount += out.spend_meta.amount;
            if (confirmed_image_match)
            {
              ++confirmed_image_skipped_count;
              if (std::numeric_limits<std::uint64_t>::max() - confirmed_image_skipped_amount < out.spend_meta.amount)
                return {lws::error::bad_daemon_response};
              confirmed_image_skipped_amount += out.spend_meta.amount;
            }
            if (debug && candidate_spent_samples < 8)
            {
              MINFO("/get_unspent_outs possible-spend skipped sample[" << candidate_spent_samples << "]: tx_hash="
                    << epee::string_tools::pod_to_hex(out.link.tx_hash)
                    << " global_index=" << out.spend_meta.id.low
                    << " amount_bucket=" << out.spend_meta.id.high
                    << " output_index=" << out.spend_meta.index
                    << " amount=" << out.spend_meta.amount
                    << " possible_spend_key_images=" << spend_images->size()
                    << " confirmed_image_match=" << confirmed_image_match
                    << " confirmed_sources_match=" << (confirmed_sources.count(out.spend_meta.id) != 0));
              for (std::size_t image_index = 0; image_index < spend_images->size(); ++image_index)
              {
                MINFO("/get_unspent_outs possible-spend image sample[" << candidate_spent_samples << "][" << image_index << "]: key_image="
                      << epee::string_tools::pod_to_hex((*spend_images)[image_index])
                      << " confirmed=" << (confirmed_images.count((*spend_images)[image_index]) != 0));
              }
              ++candidate_spent_samples;
            }
            continue;
          }

          if (confirmed_sources.count(out.spend_meta.id) != 0)
          {
            ++confirmed_source_skipped_count;
            if (std::numeric_limits<std::uint64_t>::max() - confirmed_source_skipped_amount < out.spend_meta.amount)
              return {lws::error::bad_daemon_response};
            confirmed_source_skipped_amount += out.spend_meta.amount;
            continue;
          }

          const bool locally_pending_spent = std::any_of(
            pending_active.begin(), pending_active.end(), [&out] (const db::pending_spend& pending)
            {
              return pending_spend_matches_output(pending, out);
            }
          );
          if (locally_pending_spent)
          {
            ++pending_source_skipped_count;
            if (std::numeric_limits<std::uint64_t>::max() - pending_source_skipped_amount < out.spend_meta.amount)
              return {lws::error::bad_daemon_response};
            pending_source_skipped_amount += out.spend_meta.amount;
            continue;
          }

          received += out.spend_meta.amount;
          unspent.push_back({out, {}});
          ++clean_returned_count;
          if (std::numeric_limits<std::uint64_t>::max() - clean_returned_amount < out.spend_meta.amount)
            return {lws::error::bad_daemon_response};
          clean_returned_amount += out.spend_meta.amount;
        }

        auto additional_tx_pub_keys = fetch_additional_tx_pub_keys(unspent, daemon_client);
        if (!additional_tx_pub_keys)
          return additional_tx_pub_keys.error();

        std::vector<rpc::get_unspent_outs_response::unspent_output> response_outputs{};
        response_outputs.reserve(unspent.size());
        for (auto& output : unspent)
        {
          auto tx_additional = additional_tx_pub_keys->find(output.first.link.tx_hash);
          if (tx_additional == additional_tx_pub_keys->end())
            return {lws::error::bad_daemon_response};

          log_unspent_output_debug(response_outputs.size(), output.first, debug);
          response_outputs.push_back(rpc::get_unspent_outs_response::unspent_output{
            std::move(output.first),
            std::move(output.second),
            std::move(tx_additional->second)
          });
        }

        if (debug)
        {
          MINFO("/get_unspent_outs selection summary: outputs=" << outputs->count()
                << " patch_marker=" << lws_spent_state_patch_marker
                << " balance_policy=not_applicable"
                << " unspent_policy=skip_any_possible_spend_image"
                << " spends=" << spends->count()
                << " confirmed_spend_images=" << confirmed_images.size()
                << " confirmed_sources=" << confirmed_sources.size()
                << " pending_spends_loaded=" << pending_loaded_count
                << " pending_spends_active=" << pending_active_count
                << " pending_spends_expired=" << pending_expired_count
                << " pending_source_skipped_count=" << pending_source_skipped_count
                << " pending_source_skipped_amount=" << pending_source_skipped_amount
                << " confirmed_source_skipped_count=" << confirmed_source_skipped_count
                << " confirmed_source_skipped_amount=" << confirmed_source_skipped_amount
                << " confirmed_image_skipped_count=" << confirmed_image_skipped_count
                << " confirmed_image_skipped_amount=" << confirmed_image_skipped_amount
                << " dust_or_mixin_skipped_count=" << dust_or_mixin_skipped_count
                << " dust_or_mixin_skipped_amount=" << dust_or_mixin_skipped_amount
                << " returned_outputs=" << response_outputs.size()
                << " returned_amount=" << received
                << " clean_returned_count=" << clean_returned_count
                << " clean_returned_amount=" << clean_returned_amount
                << " candidate_spent_hidden_count=" << candidate_spent_hidden_count
                << " candidate_spent_hidden_amount=" << candidate_spent_hidden_amount
                << " requested_amount=" << std::uint64_t(req.amount)
                << " dust_threshold=" << std::uint64_t(*req.dust_threshold)
                << " requested_mixin=" << std::uint64_t(*req.mixin));
        }

        if (received < std::uint64_t(req.amount))
          return {lws::error::not_enough_amount};

        if (rpc->size_scale == 0 || 1024 < rpc->size_scale || rpc->fee_mask == 0)
          return {lws::error::bad_daemon_response};

        const std::uint64_t per_byte_fee =
          rpc->estimated_base_fee / rpc->size_scale;

        return json_response(
          async_response{
            per_byte_fee,
            rpc->fee_mask,
            rpc::safe_uint64(received),
            to_uint(user->first.lookahead_fail),
            std::move(response_outputs),
            std::vector<std::uint64_t>{rpc->estimated_base_fee},
            std::move(req.creds.key)
          }
        );
      }

      static expect<response> handle(request&& req, connection_data& data, std::function<async_complete>&& resume)
      {
        struct frame
        {
          rest_server_data* parent;
          epee::byte_slice out;
          std::string in;
          net::zmq::async_client client;
          boost::asio::steady_timer timer;
          boost::asio::io_context::strand strand;
          std::vector<std::pair<request, std::function<async_complete>>> resumers;

          frame(rest_server_data& parent, net::zmq::async_client client)
            : parent(std::addressof(parent)),
              out(),
              in(),
              client(std::move(client)),
              timer(parent.io),
              strand(parent.io),
              resumers()
          {
            rpc_command::Request req{};
            req.num_grace_blocks = 10;
            out = rpc::client::make_message("get_dynamic_fee_estimate", req);
          }
        };

        struct cached_result
        {
          std::weak_ptr<frame> status;
          rpc_command::Response result;
          std::chrono::steady_clock::time_point last;
          boost::mutex sync;

          cached_result() noexcept
            : status(), result{}, last(std::chrono::seconds{0}), sync()
          {}
        };

        static cached_result cache;
        boost::unique_lock<boost::mutex> lock{cache.sync};

        if (std::chrono::steady_clock::now() - cache.last < daemon_cache_timeout)
        {
          rpc_command::Response result = cache.result;
          lock.unlock();
          return generate_response(std::move(req), std::move(result), data.global->disk.clone(), data.global->client, data.global->options.debug);
        }

        auto active = cache.status.lock();
        if (active)
        {
          active->resumers.emplace_back(std::move(req), std::move(resume));
          return async_ready();
        }

        struct async_handler : public boost::asio::coroutine
        {
          std::shared_ptr<frame> self_;

          explicit async_handler(std::shared_ptr<frame> self)
            : boost::asio::coroutine(), self_(std::move(self))
          {}

          void send_response(const boost::system::error_code error, expect<rpc_command::Response> value)
          {
            assert(self_ != nullptr);
            assert(self_->strand.running_in_this_thread());

            if (error)
            {
              MERROR("Failure in /get_unspent_outs: " << error.message());
              value = {lws::error::daemon_timeout}; // old previous behavior
            }
            else
            {
              // only re-use REQ socket if in proper state
              MDEBUG("Completed ZMQ request in /get_unspent_outs");
              self_->parent->store_async_client(std::move(self_->client));
            }

            std::vector<std::pair<request, std::function<async_complete>>> resumers;
            {
              const boost::lock_guard<boost::mutex> lock{cache.sync};
              cache.status.reset(); // prevent more resumers being added
              resumers.swap(self_->resumers);
              if (value)
              {
                cache.result = *value;
                cache.last = std::chrono::steady_clock::now();
              }
              else
                cache.result = rpc_command::Response{};
            }

            // if `value` is error, it will return immediately
            for (auto& r : resumers)
              r.second(generate_response(std::move(r.first), value, self_->parent->disk.clone(), self_->parent->client, self_->parent->options.debug));
          }

          bool set_timeout(std::chrono::steady_clock::duration timeout, const bool expecting) const
          {
            struct on_timeout
            {
              std::shared_ptr<frame> self_;

              void operator()(boost::system::error_code error) const
              {
                if (!self_ || error == boost::asio::error::operation_aborted)
                  return;

                assert(self_->strand.running_in_this_thread());
                MWARNING("Timeout on /get_unspent_outs ZMQ call");
                self_->client.close = true;
                self_->client.asock->cancel(error);
              }
            };

            assert(self_ != nullptr);
            if (!self_->timer.expires_after(timeout) && expecting)
              return false;

            self_->timer.async_wait(boost::asio::bind_executor(self_->strand, on_timeout{self_}));
            return true;
          }

          void operator()(boost::system::error_code error = {}, const std::size_t bytes = 0)
          {
            using default_response = rpc_command::Response;

            if (!self_)
              return;
            if (error)
              return send_response(error, default_response{});

            frame& self = *self_;
            assert(self.strand.running_in_this_thread());
            BOOST_ASIO_CORO_REENTER(*this)
            {
              set_timeout(std::chrono::seconds{2}, false);
              BOOST_ASIO_CORO_YIELD net::zmq::async_write(
                self.client, std::move(self.out), boost::asio::bind_executor(self.strand, std::move(*this))
              );

              if (!set_timeout(std::chrono::seconds{5}, true))
                return send_response(boost::asio::error::operation_aborted, default_response{});

              BOOST_ASIO_CORO_YIELD net::zmq::async_read(
                self.client, self.in, boost::asio::bind_executor(self.strand, std::move(*this))
              );

              if (!self.timer.cancel())
                return send_response(boost::asio::error::operation_aborted, default_response{});

              {
                rpc_command::Response daemon_resp{};
                const expect<void> status =
                  rpc::parse_response(daemon_resp, std::move(self.in));
                if (!status)
                  return send_response({}, status.error());
                return send_response({}, std::move(daemon_resp));
              }
            }
          }
        };

        expect<net::zmq::async_client> client = data.global->get_async_client();
        if (!client)
          return client.error();

        active = std::make_shared<frame>(*data.global, std::move(*client));
        cache.result = rpc_command::Response{};
        cache.status = active;
        active->resumers.emplace_back(std::move(req), std::move(resume));
        lock.unlock();

        MDEBUG("Starting new ZMQ request in /get_unspent_outs");
        boost::asio::dispatch(active->strand, async_handler{active});
        return async_ready();
      }
    };

    struct get_version
    {
      using request = rpc::get_version_request;
      using response = rpc::get_version_response;

      static expect<response> handle(request, const connection_data& data, std::function<async_complete>&&)
      {
        lws::db::block_id height{};
        {
          auto reader = data.global->disk.start_read();
          if (reader)
          {
            auto db_height = reader->get_last_block();
            if (db_height)
              height = db_height->id;
            else
              MWARNING("Failed to get DB height: " << db_height.error().message());
          }
          else
            MWARNING("Failed to start db reader: " << reader.error().message());
        }

        // response constructor fills remaining fields
        return response{height, data.global->options.max_subaddresses};
      }
    };

    struct import_request
    {
      using request = rpc::import_request;
      using response = rpc::import_response;

      static expect<response> handle(request req, connection_data& data, std::function<async_complete>&&)
      {
        bool new_request = false;
        bool fulfilled = false;
        db::address_index lookahead{};
        {
          auto user = open_account(req.creds, data.global->disk.clone());
          if (!user)
            return user.error();

          data.passed_login = true;
          if (!check_lookahead(data, req.lookahead))
            return {lws::error::max_subaddresses};

          const auto expanded_depth = [&req] (const auto& record)
          { return db::block_id(req.from_height) < record.start_height; };

          const auto change_lookahead = [&req] (const auto& record)
          {
            return record.lookahead.maj_i != req.lookahead.maj_i ||
              record.lookahead.min_i != req.lookahead.min_i;
          };

          lookahead = user->first.lookahead;
          const bool lookahead_fail = user->first.lookahead_fail != db::block_id(0);
          if (!expanded_depth(user->first) && !change_lookahead(user->first) && !lookahead_fail)
            fulfilled = true;
          else
          {
            const expect<db::request_info> info =
              user->second.get_request(db::request::import_scan, req.creds.address);

            if (!info)
            {
              if (info != lmdb::error(MDB_NOTFOUND))
                return info.error();

              // Shrink immediately if possible
              if (!lookahead_fail && req.lookahead.maj_i <= user->first.lookahead.maj_i && req.lookahead.min_i <= user->first.lookahead.min_i)
              {
                fulfilled = !expanded_depth(user->first);
                new_request = !fulfilled;
                // if not same
                if (user->first.lookahead.maj_i != req.lookahead.maj_i && user->first.lookahead.min_i != req.lookahead.min_i)
                {
                  MONERO_CHECK(data.global->disk.clone().shrink_lookahead(req.creds.address, req.lookahead));
                  lookahead = req.lookahead;
                }
              }
              else
                new_request = true;
            }
          }
        } // close reader

        if (new_request)
        {
          auto disk = data.global->disk.clone();
          MONERO_CHECK(disk.import_request(req.creds.address, db::block_id(req.from_height), req.lookahead));

          if (data.global->options.auto_accept_import)
          {
            const auto accepted = disk.accept_requests(db::request::import_scan, {std::addressof(req.creds.address), 1}, data.global->options.max_subaddresses);
            if (!accepted)
            {
              MERROR("Failed to import account " << db::address_string(req.creds.address) << ": " << accepted.error());
              lookahead = {};
            }
            else
            {
              lookahead = req.lookahead;
              fulfilled = true;
            }
          }
        }

        const char* status = new_request ?
          "Accepted, waiting for approval" : (fulfilled ? "Approved" : "Waiting for Approval");
        return response{rpc::safe_uint64(0), status, lookahead, new_request, fulfilled};
      }
    };

    struct import_key_images
    {
      using request = rpc::import_key_images_request;
      using response = rpc::import_key_images_response;

      static expect<response> handle(request req, connection_data& data, std::function<async_complete>&&)
      {
        auto user = open_account(req.creds, data.global->disk.clone());
        if (!user)
          return user.error();

        data.passed_login = true;
        const db::account account = user->first;
        MINFO("/import_key_images begin: account_id=" << unsigned(account.id)
              << " key_images=" << req.key_images.size()
              << " debug=" << data.global->options.debug
              << " initial_reader_active=1");

        struct import_key_image_debug
        {
          crypto::key_image key_image;
          boost::optional<rpc::safe_uint64> output_index;
          bool has_exact_source;
          boost::optional<db::output_id> known_source;
          bool before_spent;
        };

        std::vector<import_key_image_debug> debug_rows{};
        if (data.global->options.debug)
        {
          std::set<crypto::key_image, key_image_less> confirmed_before{};
          {
            auto confirmed = user->second.get_confirmed_spend_images(account.id);
            if (!confirmed)
              return confirmed.error();
            for (const auto& image : confirmed->make_range())
              confirmed_before.insert(image);
          }

          std::vector<std::pair<crypto::key_image, db::output_id>> known_spend_sources{};
          {
            auto spends = user->second.get_spends(account.id);
            if (!spends)
              return spends.error();
            known_spend_sources.reserve(spends->count());
            for (const auto& spend : spends->make_range())
              known_spend_sources.push_back({spend.image, spend.source});
          }

          debug_rows.reserve(req.key_images.size());
          for (const auto& key_image : req.key_images)
          {
            boost::optional<db::output_id> known_source{};
            for (const auto& known : known_spend_sources)
            {
              if (key_image_equal(known.first, key_image.key_image))
              {
                known_source = known.second;
                break;
              }
            }

            debug_rows.push_back(import_key_image_debug{
              key_image.key_image,
              key_image.output_index,
              bool(key_image.amount && key_image.global_index && key_image.tx_hash && key_image.public_key && key_image.output_index),
              known_source,
              confirmed_before.count(key_image.key_image) != 0
            });
          }
        }

        std::vector<crypto::key_image> key_images{};
        key_images.reserve(req.key_images.size());
        std::vector<db::key_image_source> key_image_sources{};
        key_image_sources.reserve(req.key_images.size());
        for (const auto& key_image : req.key_images)
        {
          key_images.push_back(key_image.key_image);

          if (key_image.amount && key_image.global_index && key_image.tx_hash && key_image.public_key && key_image.output_index)
          {
            db::key_image_source source{};
            source.image = key_image.key_image;
            source.source = db::output_id{std::uint64_t(*key_image.amount), std::uint64_t(*key_image.global_index)};
            source.tx_hash = *key_image.tx_hash;
            source.pub = *key_image.public_key;
            source.out_index = std::uint32_t(std::uint64_t(*key_image.output_index));
            key_image_sources.push_back(source);
          }
        }

        user->second.finish_read();

        MINFO("/import_key_images before_write: account_id=" << unsigned(account.id)
              << " key_images=" << key_images.size()
              << " exact_sources=" << key_image_sources.size()
              << " initial_reader_active=0");
        auto result = data.global->disk.clone().import_key_images(account.id, epee::to_span(key_images), epee::to_span(key_image_sources));
        if (!result)
        {
          MERROR("/import_key_images write_failed: account_id=" << unsigned(account.id)
                 << " key_images=" << key_images.size()
                 << " exact_sources=" << key_image_sources.size()
                 << " error=" << result.error().message()
                 << " initial_reader_active=0");
          return result.error();
        }
        MINFO("/import_key_images after_write: account_id=" << unsigned(account.id)
              << " imported=" << std::uint64_t(result->imported)
              << " confirmed_spends=" << std::uint64_t(result->confirmed_spends)
              << " unconfirmed=" << std::uint64_t(result->unconfirmed)
              << " unique_inputs=" << result->unique_inputs
              << " known_spend_inputs=" << result->known_spend_inputs
              << " already_confirmed=" << result->already_confirmed
              << " exact_source_candidates=" << result->exact_source_candidates
              << " exact_source_known_spend=" << result->exact_source_known_spend
              << " exact_source_unknown_spend=" << result->exact_source_unknown_spend
              << " exact_source_matched_output=" << result->exact_source_matched_output
              << " exact_source_missing_output=" << result->exact_source_missing_output
              << " exact_source_inserted=" << result->exact_source_inserted
              << " exact_source_already_present=" << result->exact_source_already_present
              << " initial_reader_active=0");

        maybe_auto_rescan_after_key_images(*data.global, account, *result);

        if (data.global->options.debug)
        {
          MINFO("/import_key_images before_after_read: account_id=" << unsigned(account.id)
                << " initial_reader_active=0");
          auto after_user = open_account(req.creds, data.global->disk.clone());
          if (!after_user)
          {
            MERROR("/import_key_images after_read_failed: account_id=" << unsigned(account.id)
                   << " error=" << after_user.error().message()
                   << " initial_reader_active=0");
            return after_user.error();
          }

          std::set<crypto::key_image, key_image_less> confirmed_after{};
          {
            auto confirmed = after_user->second.get_confirmed_spend_images(after_user->first.id);
            if (!confirmed)
              return confirmed.error();
            for (const auto& image : confirmed->make_range())
              confirmed_after.insert(image);
          }
          after_user->second.finish_read();

          for (std::size_t index = 0; index < debug_rows.size(); ++index)
          {
            const auto& row = debug_rows[index];
            MINFO("/import_key_images key_image[" << index << "]: key_image="
                  << epee::string_tools::pod_to_hex(row.key_image)
                  << " output_index=" << (row.output_index ? std::to_string(std::uint64_t(*row.output_index)) : std::string{"null"})
                  << " has_exact_source=" << row.has_exact_source
                  << " known_spend=" << bool(row.known_source)
                  << " known_source_global_index=" << (row.known_source ? std::to_string(row.known_source->low) : std::string{"null"})
                  << " known_source_amount_bucket=" << (row.known_source ? std::to_string(row.known_source->high) : std::string{"null"})
                  << " before_spent=" << row.before_spent
                  << " after_spent=" << (confirmed_after.count(row.key_image) != 0));
          }

          MINFO("/import_key_images summary: requested=" << req.key_images.size()
                << " unique_confirmed_after=" << confirmed_after.size()
                << " imported=" << std::uint64_t(result->imported)
                << " confirmed_spends=" << std::uint64_t(result->confirmed_spends)
                << " unconfirmed=" << std::uint64_t(result->unconfirmed)
                << " exact_source_candidates=" << result->exact_source_candidates
                << " exact_source_known_spend=" << result->exact_source_known_spend
                << " exact_source_unknown_spend=" << result->exact_source_unknown_spend
                << " exact_source_matched_output=" << result->exact_source_matched_output
                << " exact_source_missing_output=" << result->exact_source_missing_output
                << " exact_source_inserted=" << result->exact_source_inserted
                << " exact_source_already_present=" << result->exact_source_already_present);
        }

        return response{
          rpc::safe_uint64(result->imported),
          rpc::safe_uint64(result->confirmed_spends),
          rpc::safe_uint64(result->unconfirmed)
        };
      }
    };

    struct login
    {
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, connection_data& data, std::function<async_complete>&&)
      {
        if (!key_check(req.creds))
          return {lws::error::bad_view_key};

        auto disk = data.global->disk.clone();
        {
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();

          const auto account = reader->get_account(req.creds.address);
          reader->finish_read();

          if (account)
          {
            if (is_hidden(account->first))
              return {lws::error::account_not_found};

            // Do not count a request for account creation as login
            data.passed_login = true;
            return response{false, bool(account->second.flags & db::account_generated_locally), account->second.lookahead};
          }
          else if (!req.create_account || account != lws::error::account_not_found)
            return account.error();
        }

        if (!check_lookahead(data, req.lookahead))
          return {lws::error::max_subaddresses};

        const auto flags = req.generated_locally ? db::account_generated_locally : db::default_account;
        const auto hooks = disk.creation_request(req.creds.address, req.creds.key, flags, req.lookahead);
        if (!hooks)
          return hooks.error();

        if (data.global->options.auto_accept_creation)
        {
          const auto accepted = disk.accept_requests(db::request::create, {std::addressof(req.creds.address), 1}, data.global->options.max_subaddresses);
          if (!accepted)
          {
            MERROR("Failed to move account " << db::address_string(req.creds.address) << " to available state: " << accepted.error());
            req.lookahead = {};
          }
          else
            data.passed_login = true;
        }
        else
          req.lookahead = {};

        if (!hooks->empty())
        {
          // webhooks are not needed for response, so just queue i/o and
          // log errors when it fails

          rpc::send_webhook_async(
            data.global->io, data.global->client, data.global->webhook_client, epee::to_span(*hooks), "json-full-new_account_hook:", "msgpack-full-new_account_hook:"
          );
        }

        return response{true, req.generated_locally, req.lookahead};
      }
    };

    struct multisig_balance
    {
      using request = rpc::multisig_balance_request;
      using response = rpc::multisig_balance_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        const auto parsed = db::address_string(req.multisig_address);
        if (!parsed)
          return {lws::error::bad_address};

        const db::multisig_address_data balance = data.global->multisig.get_balance(req.multisig_address);
        return response{
          balance.address,
          balance.total_locked,
          static_cast<std::uint32_t>(balance.transactions.size()),
          balance.primary_context
        };
      }
    };

    struct multisig_register
    {
      using request = rpc::multisig_register_tx_request;
      using response = rpc::multisig_register_tx_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        const auto parsed = db::address_string(req.multisig_address);
        if (!parsed)
          return response{false, "Invalid multisig address", 0};

        crypto::hash tx_hash{};
        if (!epee::string_tools::hex_to_pod(req.tx_hash, tx_hash))
          return response{false, "Invalid tx_hash format", 0};

        crypto::secret_key tx_secret_key{};
        if (!epee::string_tools::hex_to_pod(req.tx_key, tx_secret_key))
          return response{false, "Invalid tx_key format", 0};

        const auto decoded_amount = decode_registered_multisig_amount(
          data.global->client,
          *parsed,
          tx_hash,
          tx_secret_key
        );
        if (!decoded_amount)
          return response{false, "Failed to decode registered amount", 0};
        if (*decoded_amount == 0)
          return response{false, "Decoded amount is zero for target multisig address", 0};

        const std::string normalized_tx_hash = epee::string_tools::pod_to_hex(tx_hash);
        const auto inserted = data.global->multisig.register_tx_ex(
          req.multisig_address,
          normalized_tx_hash,
          *decoded_amount,
          req.context
        );
        if (inserted == db::multisig_store::register_tx_result::inserted)
          return response{true, "Transaction registered successfully", *decoded_amount};
        if (inserted == db::multisig_store::register_tx_result::updated)
          return response{true, "Transaction amount backfilled successfully", *decoded_amount};
        if (inserted == db::multisig_store::register_tx_result::duplicate)
          return response{true, "Transaction already registered", *decoded_amount};

        return response{false, "Failed to register transaction", 0};
      }
    };

    struct multisig_txs
    {
      using request = rpc::multisig_transactions_request;
      using response = rpc::multisig_transactions_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        const auto parsed = db::address_string(req.multisig_address);
        if (!parsed)
          return {lws::error::bad_address};

        response out{};
        out.multisig_address = req.multisig_address;

        const auto txs = data.global->multisig.get_transactions(req.multisig_address);
        out.transactions.reserve(txs.size());
        for (const auto& tx : txs)
        {
          out.transactions.push_back(rpc::multisig_tx_entry{
            tx.tx_hash,
            tx.amount,
            tx.timestamp,
            tx.context
          });
        }

        out.total_locked = data.global->multisig.get_balance(req.multisig_address).total_locked;
        return out;
      }
    };

    struct multisig_list_wallets
    {
      using request = rpc::multisig_list_wallets_request;
      using response = rpc::multisig_list_wallets_response;

      static expect<response> handle(const request&, connection_data& data, std::function<async_complete>&&)
      {
        const auto wallets = data.global->multisig.list_wallets();

        response out{};
        out.wallets.reserve(wallets.size());
        for (const auto& w : wallets)
        {
          const auto balance = data.global->multisig.get_balance(w.address);
          out.wallets.push_back(rpc::multisig_wallet_entry{
            w.wallet_id,
            w.address,
            w.context,
            w.threshold,
            w.total,
            w.participants,
            w.status,
            balance.total_locked,
            static_cast<std::uint32_t>(balance.transactions.size()),
            w.created_at
          });
        }
        return out;
      }
    };

    struct multisig_register_wallet_handler
    {
      using request = rpc::multisig_register_wallet_request;
      using response = rpc::multisig_register_wallet_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        if (req.wallet_id.empty() || req.address.empty())
          return response{false, "wallet_id and address are required"};

        db::multisig_wallet_record record{};
        record.wallet_id = req.wallet_id;
        record.address = req.address;
        record.context = req.context;
        record.threshold = req.threshold;
        record.total = req.total;
        record.participants = req.participants;
        record.status = req.status;
        record.created_at = req.created_at;

        if (!data.global->multisig.register_wallet(record))
          return response{false, "Failed to register wallet"};

        return response{true, "Wallet registered successfully"};
      }
    };

    struct provision_subaddrs
    {
      using request = rpc::provision_subaddrs_request;
      using response = rpc::new_subaddrs_response;

      static expect<response> handle(const request& req, connection_data& data, std::function<async_complete>&&)
      {
        if (!req.maj_i && !req.min_i && !req.n_min && !req.n_maj)
          return {lws::error::invalid_range};

        db::account_id id = db::account_id::invalid;
        {
          auto user = open_account(req.creds, data.global->disk.clone());
          if (!user)
            return user.error();
          id = user->first.id;
        }

        data.passed_login = true;
        const std::uint32_t major_i = req.maj_i.value_or(0);
        const std::uint32_t minor_i = req.min_i.value_or(0);
        const std::uint32_t n_major = req.n_maj.value_or(50);
        const std::uint32_t n_minor = req.n_min.value_or(500);
        const bool get_all = req.get_all.value_or(true);

        std::vector<db::subaddress_dict> new_ranges;
        std::vector<db::subaddress_dict> all_ranges;
        if (n_major && n_minor)
        {
          if (std::numeric_limits<std::uint32_t>::max() / n_major < n_minor)
            return {lws::error::max_subaddresses};
          if (data.global->options.max_subaddresses < n_major * n_minor)
            return {lws::error::max_subaddresses};

          std::vector<db::subaddress_dict> ranges;
          ranges.reserve(n_major);
          for (std::uint64_t elem : boost::counting_range(std::uint64_t(major_i), std::uint64_t(major_i) + n_major))
          {
            ranges.emplace_back(
              db::major_index(elem), db::index_ranges{{db::index_range{db::minor_index(minor_i), db::minor_index(minor_i + n_minor - 1)}}}
            );
          }
          auto upserted = data.global->disk.clone().upsert_subaddresses(id, req.creds.address, req.creds.key, ranges, data.global->options.max_subaddresses);
          if (!upserted)
            return upserted.error();
          new_ranges = std::move(*upserted);
        }

        if (get_all)
        {
          // must start a new read after the last write
          auto disk = data.global->disk.clone();
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();
          auto rc = reader->get_subaddresses(id);
          if (!rc)
            return rc.error();
          all_ranges = std::move(*rc);
        }
        return response{std::move(new_ranges), std::move(all_ranges)};
      }
    };

    struct submit_raw_tx
    {
      using request = rpc::submit_raw_tx_request;
      using response = void; // always async
      using async_response = rpc::submit_raw_tx_response;

      static expect<response> handle(request req, const connection_data& data, std::function<async_complete>&& resume)
      {
        using transaction_rpc = cryptonote::rpc::SendRawTxHex;

        struct frame
        {
          struct submit_context
          {
            epee::byte_slice message;
            std::function<async_complete> resume;
            db::account_id pending_account;
            std::vector<db::pending_spend> pending_spends;

            submit_context(epee::byte_slice message, std::function<async_complete>&& resume, db::account_id pending_account, std::vector<db::pending_spend>&& pending_spends)
              : message(std::move(message)),
                resume(std::move(resume)),
                pending_account(pending_account),
                pending_spends(std::move(pending_spends))
            {}
          };

          rest_server_data* parent;
          std::string in;
          net::zmq::async_client client;
          boost::asio::steady_timer timer;
          boost::asio::io_context::strand strand;
          std::deque<submit_context> resumers;

          frame(rest_server_data& parent, net::zmq::async_client client)
            : parent(std::addressof(parent)),
              in(),
              client(std::move(client)),
              timer(parent.io),
              strand(parent.io),
              resumers()
          {}
        };

        struct cached_result
        {
          std::weak_ptr<frame> status;
          boost::mutex sync;

          cached_result() noexcept
            : status(), sync()
          {}
        };

        transaction_rpc::Request daemon_req{};
        daemon_req.relay = true;
        daemon_req.tx_as_hex = std::move(req.tx);

        db::account_id pending_account = db::account_id::invalid;
        std::vector<db::pending_spend> pending_spends{};
        if (!req.pending_spent_outputs.empty())
        {
          if (!req.creds)
            return {lws::error::bad_client_tx};
          auto user = open_account(*req.creds, data.global->disk.clone());
          if (!user)
            return user.error();

          const db::account_time recorded{std::uint32_t(std::min<std::uint64_t>(unix_timestamp_now(), std::numeric_limits<std::uint32_t>::max()))};
          pending_account = user->first.id;
          pending_spends.reserve(req.pending_spent_outputs.size());
          for (const auto& pending : req.pending_spent_outputs)
          {
            pending_spends.push_back(db::pending_spend{
              db::output_id{std::uint64_t(pending.amount), std::uint64_t(pending.global_index)},
              pending.tx_hash,
              pending.public_key,
              pending.out_index,
              recorded
            });
          }
        }

        if (data.global->options.debug)
        {
          const auto& tx_hex = daemon_req.tx_as_hex;
          const std::size_t preview_len = std::min<std::size_t>(64, tx_hex.size());
          MINFO("/submit_raw_tx received: tx_hex_len=" << tx_hex.size()
                << " tx_bytes=" << (tx_hex.size() / 2)
                << " prefix=" << tx_hex.substr(0, preview_len)
                << " suffix=" << (tx_hex.size() > preview_len ? tx_hex.substr(tx_hex.size() - preview_len) : tx_hex));
          MINFO("/submit_raw_tx preparing daemon call: method=send_raw_tx_hex relay=" << daemon_req.relay
                << " payload_size=" << tx_hex.size());
        }

        epee::byte_slice msg = rpc::client::make_message("send_raw_tx_hex", daemon_req);

        static cached_result cache;
        boost::unique_lock<boost::mutex> lock{cache.sync};

        auto active = cache.status.lock();
        if (active)
        {
          active->resumers.emplace_back(std::move(msg), std::move(resume), pending_account, std::move(pending_spends));
          return success();
        }

        struct async_handler : public boost::asio::coroutine
        {
          std::shared_ptr<frame> self_;

          explicit async_handler(std::shared_ptr<frame> self)
            : boost::asio::coroutine(), self_(std::move(self))
          {}

          void send_response(const boost::system::error_code error, expect<copyable_slice> value)
          {
            assert(self_ != nullptr);
            assert(self_->strand.running_in_this_thread());

            std::deque<frame::submit_context> resumers;
            {
              const boost::lock_guard<boost::mutex> lock{cache.sync};
              if (error)
              {
                // Prevent further resumers, ZMQ REQ/REP in bad state
                MERROR("/submit_raw_tx ZMQ/IO error: " << error.message());
                MERROR("Failure in /submit_raw_tx: " << error.message());
                value = {lws::error::daemon_timeout};
                cache.status.reset();
                resumers.swap(self_->resumers);
              }
              else
              {
                MDEBUG("Completed ZMQ request in /submit_raw_tx");
                resumers.push_back(std::move(self_->resumers.front()));
                self_->resumers.pop_front();
              }
            }

            for (const auto& r : resumers)
              r.resume(value);
          }

          bool set_timeout(std::chrono::steady_clock::duration timeout, const bool expecting) const
          {
            struct on_timeout
            {
              std::shared_ptr<frame> self_;

              void operator()(boost::system::error_code error) const
              {
                if (!self_ || error == boost::asio::error::operation_aborted)
                  return;

                assert(self_->strand.running_in_this_thread());
                MWARNING("Timeout on /submit_raw_tx ZMQ call");
                self_->client.close = true;
                self_->client.asock->cancel(error);
              }
            };

            assert(self_ != nullptr);
            if (!self_->timer.expires_after(timeout) && expecting)
              return false;

            self_->timer.async_wait(boost::asio::bind_executor(self_->strand, on_timeout{self_}));
            return true;
          }

          void operator()(boost::system::error_code error = {}, const std::size_t bytes = 0)
          {
            if (!self_)
              return;
            if (error)
              return send_response(error, async_ready());

            frame& self = *self_;
            assert(self.strand.running_in_this_thread());
            epee::byte_slice next = nullptr;
            BOOST_ASIO_CORO_REENTER(*this)
            {
              for (;;)
              {
                {
                  const boost::lock_guard<boost::mutex> lock{cache.sync};
                  if (self_->resumers.empty())
                  {
                    cache.status.reset();
                    self_->parent->store_async_client(std::move(self_->client));
                    return;
                  }
                  next = std::move(self_->resumers.front().message);
                }

                set_timeout(std::chrono::seconds{10}, false);
                BOOST_ASIO_CORO_YIELD net::zmq::async_write(
                  self.client, std::move(next), boost::asio::bind_executor(self.strand, std::move(*this))
                );

                if (!set_timeout(std::chrono::seconds{20}, true))
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                self.in.clear(); // could be in moved-from state
                BOOST_ASIO_CORO_YIELD net::zmq::async_read(
                  self.client, self.in, boost::asio::bind_executor(self.strand, std::move(*this))
                );

                if (!self.timer.cancel())
                  return send_response(boost::asio::error::operation_aborted, async_ready());

                {
                  transaction_rpc::Response daemon_resp{};
                  const std::string daemon_raw_response = self.in;
                  if (self.parent->options.debug)
                    MINFO("/submit_raw_tx daemon raw response (" << daemon_raw_response.size() << " bytes): "
                          << daemon_raw_response.substr(0, 1024));
                  const expect<void> status =
                    rpc::parse_response(daemon_resp, std::move(self.in));

                  if (!status)
                  {
                    if (self.parent->options.debug)
                      MWARNING("/submit_raw_tx BRANCH[parse_failed]: " << status.error().message()
                               << " | raw_response_preview=" << daemon_raw_response.substr(0, 512));
                    if (should_passthrough_submit_raw_tx_error(daemon_raw_response, self.parent->options.debug))
                    {
                      MWARNING("/submit_raw_tx passthrough daemon error body after parse failure");
                      send_response({}, raw_json_response(daemon_raw_response));
                    }
                    else
                    {
                      send_response({}, status.error());
                    }
                  }
                  else if (!daemon_resp.relayed)
                  {
                    if (self.parent->options.debug)
                      MWARNING("/submit_raw_tx BRANCH[relay_rejected]: relayed=" << daemon_resp.relayed
                               << " | raw_response=" << daemon_raw_response.substr(0, 512));
                    if (should_passthrough_submit_raw_tx_error(daemon_raw_response, self.parent->options.debug))
                    {
                      MWARNING("/submit_raw_tx passthrough daemon relay rejection body");
                      send_response({}, raw_json_response(daemon_raw_response));
                    }
                    else
                    {
                      send_response({}, {lws::error::tx_relay_failed});
                    }
                  }
                  else
                  {
                    const auto& current = self.resumers.front();
                    if (!current.pending_spends.empty())
                    {
                      const auto stored = self.parent->disk.clone().record_pending_spends(
                        current.pending_account, epee::to_span(current.pending_spends)
                      );
                      if (!stored)
                      {
                        MWARNING("/submit_raw_tx pending_spends persist failed after relay success: " << stored.error().message());
                      }
                      else if (self.parent->options.debug)
                      {
                        MINFO("/submit_raw_tx pending_spends persisted: account_id=" << unsigned(current.pending_account)
                              << " count=" << current.pending_spends.size());
                      }
                    }
                    if (self.parent->options.debug)
                      MINFO("/submit_raw_tx BRANCH[success]: relayed=true");
                    send_response({}, json_response(async_response{"OK"}));
                  }
                }
              }
            }
          }
        };

        expect<net::zmq::async_client> client = data.global->get_async_client();
        if (!client)
          return client.error();

        active = std::make_shared<frame>(*data.global, std::move(*client));
        cache.status = active;

        active->resumers.emplace_back(std::move(msg), std::move(resume), pending_account, std::move(pending_spends));
        lock.unlock();

        MDEBUG("Starting new ZMQ request in /submit_raw_tx");
        boost::asio::dispatch(active->strand, async_handler{active});
        return success();
      }
    };

    struct upsert_subaddrs
    {
      using request = rpc::upsert_subaddrs_request;
      using response = rpc::new_subaddrs_response;

      static expect<response> handle(request req, connection_data& data, std::function<async_complete>&&)
      {
        if (!data.global->options.max_subaddresses)
          return {lws::error::max_subaddresses};

        db::account_id id = db::account_id::invalid;
        {
          auto user = open_account(req.creds, data.global->disk.clone());
          if (!user)
            return user.error();
          id = user->first.id;
        }

        data.passed_login = true;
        const bool get_all = req.get_all.value_or(true);

        std::vector<db::subaddress_dict> all_ranges;
        auto disk = data.global->disk.clone();
        auto new_ranges =
          disk.upsert_subaddresses(id, req.creds.address, req.creds.key, req.subaddrs, data.global->options.max_subaddresses);
        if (!new_ranges)
          return new_ranges.error();

        if (get_all)
        {
          auto reader = data.global->disk.start_read();
          if (!reader)
            return reader.error();
          auto rc = reader->get_subaddresses(id);
          if (!rc)
            return rc.error();
          all_ranges = std::move(*rc);
        }
        return response{std::move(*new_ranges), std::move(all_ranges)};
      }
    };

    template<typename E>
    expect<epee::byte_slice> call(std::string&& root, connection_data& data, std::function<async_complete>&& resume)
    {
      using request = typename E::request;
      using response = typename E::response;

      if (std::is_same<void, response>() && !resume)
        throw std::logic_error{"async REST handler not setup properly"};
      if (std::is_same<epee::byte_slice, response>() && !resume)
        throw std::logic_error{"async REST handler not setup properly"};

      request req{};
      if (!std::is_empty<request>())
      {
        if (data.last_verb != boost::beast::http::verb::post)
          return {error::bad_verb};
        std::error_code error = wire::json::from_bytes(std::move(root), req);
        if (error)
          return error;
      }

      expect<response> resp = E::handle(std::move(req), data, std::move(resume));
      if (!resp)
        return resp.error();
      return json_response(std::move(resp));
    }

    template<typename T>
    struct admin
    {
      T params;
      boost::optional<crypto::secret_key> auth;
    };

    template<typename T>
    void read_bytes(wire::json_reader& source, admin<T>& self)
    {
        wire::object(source, WIRE_OPTIONAL_FIELD(auth), WIRE_FIELD(params));
    }
    void read_bytes(wire::json_reader& source, admin<expect<void>>& self)
    {
        // params optional
        wire::object(source, WIRE_OPTIONAL_FIELD(auth));
    }

    template<typename E>
    expect<epee::byte_slice> call_admin(std::string&& root, connection_data& data, std::function<async_complete>&&)
    {
      using request = typename E::request;

      if (data.last_verb != boost::beast::http::verb::post)
        return {error::bad_verb};

      admin<request> req{};
      {
        const std::error_code error = wire::json::from_bytes(std::move(root), req);
        if (error)
          return error;
      }

      rpc::add_values(req.params, data.global->options); // add max_subaddresses
      db::storage disk = data.global->disk.clone();
      if (!data.global->options.disable_admin_auth)
      {
        if (!req.auth)
          return {error::account_not_found};

        db::account_address address{};
        if (!crypto::secret_key_to_public_key(*(req.auth), address.view_public))
          return {error::crypto_failure};

        auto reader = disk.start_read();
        if (!reader)
          return reader.error();
        const auto account = reader->get_account(address);
        if (!account)
          return account.error();
        if (account->first == db::account_status::inactive)
          return {error::account_not_found};
        if (!(account->second.flags & db::account_flags::admin_account))
          return {error::account_not_found};
      }

      wire::json_slice_writer dest{};
      MONERO_CHECK(E{}(dest, std::move(disk), std::move(req.params)));
      return epee::byte_slice{dest.take_sink()};
    }

    struct endpoint
    {
      char const* const name;
      expect<epee::byte_slice> (*const run)(std::string&&, connection_data&, std::function<async_complete>&&);
      const unsigned max_size;
      const bool is_async;
    };

    constexpr unsigned get_max(const endpoint* start, endpoint const* const end) noexcept
    {
      unsigned current_max = 0;
      for ( ; start != end; ++start)
        current_max = std::max(current_max, start->max_size);
      return current_max;
    }

    constexpr const endpoint endpoints[] =
    {
      {"/daemon_status",         call<daemon_status>,          1024,  true},
      {"/get_address_info",      call<get_address_info>,   2 * 1024, false},
      {"/get_address_txs",       call<get_address_txs>,    2 * 1024, false},
      {"/get_random_outs",       call<get_random_outs>,    2 * 1024,  true},
      {"/get_subaddrs",          call<get_subaddrs>,       2 * 1024, false},
      {"/get_txt_records",       nullptr,                         0, false},
      {"/get_unspent_outs",      call<get_unspent_outs>,   2 * 1024,  true},
      {"/get_version",           call<get_version>,            1024, false},
      {"/import_key_images",     call<import_key_images>, 64 * 1024, false},
      {"/import_wallet_request", call<import_request>,     2 * 1024, false},
      {"/login",                 call<login>,              2 * 1024, false},
      {"/multisig/balance",          call<multisig_balance>,                  2 * 1024, false},
      {"/multisig/register_tx",      call<multisig_register>,                 4 * 1024, false},
      {"/multisig/register_wallet",  call<multisig_register_wallet_handler>,  4 * 1024, false},
      {"/multisig/transactions",     call<multisig_txs>,                      2 * 1024, false},
      {"/multisig/wallets",          call<multisig_list_wallets>,             1024,     false},
      {"/provision_subaddrs",    call<provision_subaddrs>, 2 * 1024, false},
      {"/submit_raw_tx",         call<submit_raw_tx>,    512 * 1024,  true},
      {"/upsert_subaddrs",       call<upsert_subaddrs>,   10 * 1024, false}
    };
    constexpr const unsigned max_standard_endpoint_size =
      get_max(std::begin(endpoints), std::end(endpoints));

    constexpr const endpoint admin_endpoints[] =
    {
      {"/accept_requests",       call_admin<rpc::accept_requests_>, 50 * 1024, false},
      {"/add_account",           call_admin<rpc::add_account_>,     50 * 1024, false},
      {"/list_accounts",         call_admin<rpc::list_accounts_>,         100, false},
      {"/list_requests",         call_admin<rpc::list_requests_>,         100, false},
      {"/modify_account_status", call_admin<rpc::modify_account_>,  50 * 1024, false},
      {"/reject_requests",       call_admin<rpc::reject_requests_>, 50 * 1024, false},
      {"/rescan",                call_admin<rpc::rescan_>,          50 * 1024, false},
      {"/validate",              call_admin<rpc::validate_>,        50 * 1024, false},
      {"/webhook_add",           call_admin<rpc::webhook_add_>,     50 * 1024, false},
      {"/webhook_delete",        call_admin<rpc::webhook_delete_>,  50 * 1024, false},
      {"/webhook_delete_uuid",   call_admin<rpc::webhook_del_uuid_>,50 * 1024, false},
      {"/webhook_list",          call_admin<rpc::webhook_list_>,          100, false}
    };
    constexpr const unsigned max_admin_endpoint_size =
      get_max(std::begin(endpoints), std::end(endpoints));

    constexpr const unsigned max_endpoint_size =
      std::max(max_standard_endpoint_size, max_admin_endpoint_size);

    struct by_name_
    {
      bool operator()(endpoint const& left, endpoint const& right) const noexcept
      {
        if (left.name && right.name)
          return std::strcmp(left.name, right.name) < 0;
        return false;
      }
      bool operator()(const boost::beast::string_view left, endpoint const& right) const noexcept
      {
        if (right.name)
          return left < right.name;
        return false;
      }
      bool operator()(endpoint const& left, const boost::beast::string_view right) const noexcept
      {
        if (left.name)
          return left.name < right;
        return false;
      }
    };
    constexpr const by_name_ by_name{};

    struct slice_body
    {
      using value_type = epee::byte_slice;

      static std::size_t size(const value_type& source) noexcept
      {
        return source.size();
      }

      struct writer
      {
        epee::byte_slice body_;

        using const_buffers_type = boost::asio::const_buffer;

        template<bool is_request, typename Fields>
        explicit writer(boost::beast::http::header<is_request, Fields> const&, value_type const& body)
          : body_(body.clone())
        {}

        void init(boost::beast::error_code& ec)
        {
          ec = {};
        }

        boost::optional<std::pair<const_buffers_type, bool>> get(boost::beast::error_code& ec)
        {
          ec = {};
          return {{const_buffers_type{body_.data(), body_.size()}, false}};
        }
      };
    };
  } // anonymous

  struct rest_server::internal
  {
    boost::optional<std::string> prefix;
    boost::optional<std::string> admin_prefix;
    boost::optional<boost::asio::ssl::context> ssl_;
    boost::asio::ip::tcp::acceptor acceptor;

    explicit internal(boost::asio::io_context& io)
      : prefix()
      , admin_prefix()
      , ssl_()
      , acceptor(io)
    {
      assert(std::is_sorted(std::begin(endpoints), std::end(endpoints), by_name));
    }

    const endpoint* get_endpoint(boost::beast::string_view uri) const
    {
      using span = epee::span<const endpoint>;
      span handlers = nullptr;

      if (admin_prefix && uri.starts_with(*admin_prefix))
      {
        uri.remove_prefix(admin_prefix->size());
        handlers = span{admin_endpoints};
      }
      else if (prefix && uri.starts_with(*prefix))
      {
        uri.remove_prefix(prefix->size());
        handlers = span{endpoints};
      }
      else
        return nullptr;

      const auto handler = std::lower_bound(
        std::begin(handlers), std::end(handlers), uri, by_name
      );
      if (handler == std::end(handlers) || handler->name != uri)
        return nullptr;
      return handler;
    }
  };

  template<typename Sock>
  struct rest_server::connection
  {
    internal* parent_;
    connection_data data_;
    Sock sock_;
    boost::beast::flat_static_buffer<http_parser_buffer_size> buffer_;
    boost::optional<boost::beast::http::parser<true, boost::beast::http::string_body>> parser_;
    boost::beast::http::response<net::http::slice_body> response_;
    boost::asio::steady_timer timer_;
    boost::asio::io_context::strand strand_;
    bool keep_alive_;

    static boost::asio::ip::tcp::socket make_socket(std::true_type, rest_server_data* global, internal*)
    {
      return boost::asio::ip::tcp::socket{global->io};
    }

    static boost::asio::ssl::stream<boost::asio::ip::tcp::socket> make_socket(std::false_type, rest_server_data* global, internal* parent)
    {
      return boost::asio::ssl::stream<boost::asio::ip::tcp::socket>{
        global->io, parent->ssl_.value()
      };
    }

    static boost::asio::ip::tcp::socket& get_tcp(boost::asio::ip::tcp::socket& sock)
    {
      return sock;
    }

    static boost::asio::ip::tcp::socket& get_tcp(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& sock)
    {
      return sock.next_layer();
    }

    boost::asio::ip::tcp::socket& sock() { return get_tcp(sock_); }

    explicit connection(rest_server_data* global, internal* parent) noexcept
      : parent_(parent),
        data_(global),
        sock_(make_socket(std::is_same<Sock, boost::asio::ip::tcp::socket>(), global, parent)),
        buffer_{},
        parser_{},
        response_{},
        timer_(global->io),
        strand_(global->io),
        keep_alive_(true)
    {}

    ~connection()
    {
      MDEBUG("Destroying connection " << this);
    }

    template<typename F>
    void bad_request(const boost::beast::http::status status, F&& resume)
    {
      MDEBUG("Sending HTTP status " << int(status) << " to " << this);

      assert(strand_.running_in_this_thread());
      response_ = {status, parser_->get().version()};
      response_.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
      response_.keep_alive(keep_alive_);
      response_.prepare_payload();
      resume();
    }

    template<typename F>
    void bad_request(const std::error_code error, F&& resume)
    {
      boost::system::error_code ec{};
      MINFO("REST error: " << error.message() << " from " << sock().remote_endpoint(ec) << " / " << this);

      assert(strand_.running_in_this_thread());
      if (error.category() == wire::error::rapidjson_category() || error == lws::error::invalid_range || error == lws::error::not_enough_amount)
        return bad_request(boost::beast::http::status::bad_request, std::forward<F>(resume));
      else if (error == lws::error::bad_verb)
        return bad_request(boost::beast::http::status::method_not_allowed, std::forward<F>(resume));
      else if (error == lws::error::account_not_found || error == lws::error::duplicate_request)
        return bad_request(boost::beast::http::status::forbidden, std::forward<F>(resume));
      else if (error == lws::error::max_subaddresses)
        return bad_request(boost::beast::http::status::conflict, std::forward<F>(resume));
      else if (error.default_error_condition() == std::errc::timed_out || error.default_error_condition() == std::errc::no_lock_available)
        return bad_request(boost::beast::http::status::service_unavailable, std::forward<F>(resume));
      return bad_request(boost::beast::http::status::internal_server_error, std::forward<F>(resume));
    }

    template<typename F>
    void valid_request(epee::byte_slice body, F&& resume)
    {
      MDEBUG("Sending HTTP 200 OK (" << body.size() << " bytes) to " << this);

      assert(strand_.running_in_this_thread());
      response_ = {boost::beast::http::status::ok, parser_->get().version(), std::move(body)};
      response_.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
      response_.set(boost::beast::http::field::content_type, "application/json");
      response_.keep_alive(keep_alive_);
      response_.prepare_payload();
      resume(); // runs in strand
    }

    static bool set_timeout(const std::shared_ptr<connection>& self, const std::chrono::steady_clock::duration timeout, const bool existing)
    {
      if (!self)
        return false;

      struct on_timeout
      {
        std::shared_ptr<connection> self_;

        void operator()(boost::system::error_code error) const
        {
          if (!self_ || error == boost::asio::error::operation_aborted)
            return;

          assert(self_->strand_.running_in_this_thread());
          MWARNING("Timeout on REST connection to " << self_->sock().remote_endpoint(error) << " / " << self_.get());
          self_->sock().cancel(error);
          self_->shutdown();
        }
      };

      if (!self->timer_.expires_after(timeout) && existing)
        return false; // timeout queued, just abort
      self->timer_.async_wait(boost::asio::bind_executor(self->strand_, on_timeout{self}));
      return true;
    }

    void shutdown()
    {
      boost::system::error_code ec{};
      MDEBUG("Shutting down REST socket to " << this);
      sock().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      timer_.cancel();
    }
  };

  template<typename Sock>
  struct rest_server::handler_loop : public boost::asio::coroutine
  {
    std::shared_ptr<connection<Sock>> self_;

    explicit handler_loop(std::shared_ptr<connection<Sock>> self) noexcept
      : boost::asio::coroutine(), self_(std::move(self))
    {}

    static void async_handshake(const boost::asio::ip::tcp::socket&) noexcept
    {}

    void async_handshake(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& sock)
    {
      connection<Sock>& self = *self_;
      self.sock_.async_handshake(
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::server,
        boost::asio::bind_executor(self.strand_, std::move(*this))
      );
    }

    template<typename F>
    void async_response(F&& resume)
    {
      assert(self_ != nullptr);
      assert(self_->strand_.running_in_this_thread());

      // checks access for `parser_` on first use
      self_->keep_alive_ = self_->parser_->get().keep_alive();
      const auto target = self_->parser_.value().get().target();

      MDEBUG("Received HTTP request from " << self_.get() << " to target " << target);

      // Checked access for `parser_` on first use
      endpoint const* const handler = self_->parent_->get_endpoint(target);
      if (!handler)
        return self_->bad_request(boost::beast::http::status::not_found, std::forward<F>(resume));

      if (handler->run == nullptr)
        return self_->bad_request(boost::beast::http::status::not_implemented, std::forward<F>(resume));

      const auto payload_size =
        self_->parser_->get().payload_size().value_or(std::numeric_limits<std::uint64_t>::max());
      if (handler->max_size < payload_size)
      {
        boost::system::error_code error{};
        MINFO("REST client (" << self_->sock().remote_endpoint(error) << " / " << self_.get() << ") exceeded maximum body size (" << handler->max_size << " bytes)");
        return self_->bad_request(boost::beast::http::status::bad_request, std::forward<F>(resume));
      }

      const boost::beast::http::verb verb = self_->parser_->get().method();
      if (verb != boost::beast::http::verb::post && verb != boost::beast::http::verb::get)
        return self_->bad_request(boost::beast::http::status::method_not_allowed, std::forward<F>(resume));

      std::function<async_complete> resumer;
      if (handler->is_async)
      {
        /* The `resumer` callback can be invoked in another strand (created
          by the handler function), and therefore needs to be "wrapped" to
          ensure thread safety. This also allows `resume` to be unwrapped.
          DO NOT use `boost::asio::bind_executor` here as it doesn't create
          a new callable like `wrap` does. */
        const auto& self = self_;
        resumer = self->strand_.wrap(
          [self, resume] (expect<copyable_slice> body) mutable
          {
            if (!body)
              self->bad_request(body.error(), std::move(resume));
            else
              self->valid_request(std::move(body->value), std::move(resume));
          }
        );
      }

      MDEBUG("Running REST handler " << handler->name << " on " << self_.get());
      self_->data_.last_verb = verb;
      auto body = handler->run(std::move(self_->parser_->get()).body(), self_->data_, std::move(resumer));
      if (!body)
        return self_->bad_request(body.error(), std::forward<F>(resume));
      else if (!handler->is_async || !body->empty())
        return self_->valid_request(std::move(*body), std::forward<F>(resume));
      // else wait for `resumer` to continue response coroutine
      MDEBUG("REST response to " << self_.get() << " is being generated async");
    }

    void operator()(boost::system::error_code error = {}, const std::size_t bytes = 0)
    {
      using not_ssl = std::is_same<Sock, boost::asio::ip::tcp::socket>;

      if (!self_)
        return;

      assert(self_->strand_.running_in_this_thread());
      if (error)
      {
        boost::system::error_code ec{};
        if (error != boost::asio::error::operation_aborted && error != boost::beast::http::error::end_of_stream)
          MERROR("Error on REST socket (" << self_->sock().remote_endpoint(ec) << " / " << self_.get() << "): " << error.message());
        return self_->shutdown();
      }

      connection<Sock>& self = *self_;
      const bool not_first = bool(self.parser_ || !not_ssl());
      BOOST_ASIO_CORO_REENTER(*this)
      {
        // still need if statement, otherwise YIELD exits.
        if (!not_ssl())
        {
          MDEBUG("Performing SSL handshake to " << self_.get());
          connection<Sock>::set_timeout(self_, rest_handshake_timeout, false);
          BOOST_ASIO_CORO_YIELD async_handshake(self.sock_);
        }

        for (;;)
        {
          self.parser_.emplace();
          self.parser_->body_limit(max_endpoint_size);

          if (!connection<Sock>::set_timeout(self_, self_->data_.get_request_timeout(), not_first))
            return self.shutdown();

          MDEBUG("Reading new REST request from " << self_.get());
          BOOST_ASIO_CORO_YIELD boost::beast::http::async_read(
            self.sock_, self.buffer_, *self.parser_, boost::asio::bind_executor(self.strand_, std::move(*this))
          );

          // async_response will have its own timeouts set in handlers if async
          if (!self.timer_.cancel())
            return self.shutdown();

          /* async_response flow has MDEBUG statements for outgoing messages.
           async_response will also `self_->strand_.wrap` when necessary. */
          BOOST_ASIO_CORO_YIELD async_response(handler_loop{*this});

          connection<Sock>::set_timeout(self_, rest_response_timeout, false);
          BOOST_ASIO_CORO_YIELD boost::beast::http::async_write(
            self.sock_, self.response_, boost::asio::bind_executor(self.strand_, std::move(*this))
          );

          if (!self.keep_alive_)
            return self.shutdown();
        }
      }
    }
  };

  template<typename Sock>
  struct rest_server::accept_loop : public boost::asio::coroutine
  {
    rest_server_data* global_;
    internal* parent_;
    std::shared_ptr<connection<Sock>> next_;

    explicit accept_loop(rest_server_data* global, internal* parent) noexcept
      : global_(global), parent_(parent), next_(nullptr)
    {}

    void operator()(boost::system::error_code error = {})
    {
      if (!global_ || !parent_)
        return;

      BOOST_ASIO_CORO_REENTER(*this)
      {
        for (;;)
        {
          next_ = std::make_shared<connection<Sock>>(global_, parent_);
          BOOST_ASIO_CORO_YIELD parent_->acceptor.async_accept(next_->sock(), std::move(*this));

          if (error)
          {
            MERROR("Acceptor failed: " << error.message());
          }
          else
          {
            MDEBUG("New connection to " << next_->sock().remote_endpoint(error) << " / " << next_.get());
            boost::asio::dispatch(next_->strand_, handler_loop{next_});
          }
        }
      }
    }
  };

  void rest_server::run_io()
  {
    try { global_->io.run(); }
    catch (const std::exception& e)
    {
      std::raise(SIGINT);
      MERROR("Error in REST I/O thread: " << e.what());
    }
    catch (...)
    {
      std::raise(SIGINT);
      MERROR("Unexpected error in REST I/O thread");
    }
  }

  rest_server::rest_server(epee::span<const std::string> addresses, std::vector<std::string> admin, db::storage disk, rpc::client client, configuration config)
    : global_(std::make_unique<rest_server_data>(std::move(disk), std::move(client), runtime_options{config.max_subaddresses, config.webhook_verify, config.disable_admin_auth, config.auto_accept_creation, config.auto_accept_import, config.debug, config.auto_rescan_after_key_images, config.auto_rescan_depth, config.auto_rescan_min_confirmed_spends})),
      ports_(),
      workers_()
  {
    if (addresses.empty())
      MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

    std::sort(admin.begin(), admin.end());
    const auto init_port = [this, &admin] (internal& port, const std::string& address, configuration config, const bool is_admin) -> bool
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(address, url))
        MONERO_THROW(lws::error::configuration, "REST server URL/address is invalid");

      const bool https = url.schema == "https";
      if (!https && url.schema != "http")
        MONERO_THROW(lws::error::configuration, "Unsupported scheme, only http or https supported");

      if (std::numeric_limits<std::uint16_t>::max() < url.port)
        MONERO_THROW(lws::error::configuration, "Specified port for REST server is out of range");

      if (!url.uri.empty() && url.uri.front() != '/')
        MONERO_THROW(lws::error::configuration, "First path prefix character must be '/'");

      if (!https)
      {
        boost::system::error_code error{};
        const auto ip_host = boost::asio::ip::make_address(url.host, error);
        if (error)
          MONERO_THROW(lws::error::configuration, "Invalid IP address for REST server");
        if (!ip_host.is_loopback() && !config.allow_external)
          MONERO_THROW(lws::error::configuration, "Binding to external interface with http - consider using https or secure tunnel (ssh, etc). Use --confirm-external-bind to override");
      }

      if (url.port == 0)
        url.port = https ? 8443 : 8080;

      if (!is_admin)
      {
        epee::net_utils::http::url_content admin_url{};
        const boost::string_ref start{address.c_str(), address.rfind(url.uri)};
        while (true) // try to merge 1+ admin prefixes
        {
          const auto mergeable = std::lower_bound(admin.begin(), admin.end(), start);
          if (mergeable == admin.end())
            break;

          if (!epee::net_utils::parse_url(*mergeable, admin_url))
            MONERO_THROW(lws::error::configuration, "Admin REST URL/address is invalid");
          if (admin_url.port == 0)
            admin_url.port = https ? 8443 : 8080;
          if (url.host != admin_url.host || url.port != admin_url.port)
            break; // nothing is mergeable

          if (port.admin_prefix)
            MONERO_THROW(lws::error::configuration, "Two admin REST servers cannot be merged onto one REST server");

          if (url.uri.size() < 2 || admin_url.uri.size() < 2)
            MONERO_THROW(lws::error::configuration, "Cannot merge REST server and admin REST server - a prefix must be specified for both");
          if (admin_url.uri.front() != '/')
            MONERO_THROW(lws::error::configuration, "Admin REST first path prefix character must be '/'");
          if (admin_url.uri != admin_url.m_uri_content.m_path)
            MONERO_THROW(lws::error::configuration, "Admin REST server must have path only prefix");

          MINFO("Merging admin and non-admin REST servers: " << address << " + " << *mergeable);
          port.admin_prefix = admin_url.m_uri_content.m_path;
          admin.erase(mergeable);
        } // while multiple mergable admins
      }

      if (url.uri != url.m_uri_content.m_path)
        MONERO_THROW(lws::error::configuration, "REST server must have path only prefix");

      if (url.uri.size() < 2)
        url.m_uri_content.m_path.clear();
      if (is_admin)
        port.admin_prefix = url.m_uri_content.m_path;
      else
        port.prefix = url.m_uri_content.m_path;

      epee::net_utils::ssl_options_t ssl_options = https ?
        epee::net_utils::ssl_support_t::e_ssl_support_enabled :
        epee::net_utils::ssl_support_t::e_ssl_support_disabled;
      ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
      ssl_options.auth = std::move(config.auth);

      boost::asio::ip::tcp::endpoint endpoint{
        boost::asio::ip::make_address(url.host),
        boost::lexical_cast<unsigned short>(url.port)
      };

      port.acceptor.open(endpoint.protocol());

#if !defined(_WIN32)
      port.acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
#endif

      port.acceptor.bind(endpoint);
      port.acceptor.listen();

      if (ssl_options)
      {
        port.ssl_ = ssl_options.create_context();
        accept_loop<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>{global_.get(), std::addressof(port)}();
      }
      else
        accept_loop<boost::asio::ip::tcp::socket>{global_.get(), std::addressof(port)}();
      return https;
    };

    bool any_ssl = false;
    for (const std::string& address : addresses)
    {
      ports_.emplace_back(global_->io);
      any_ssl |= init_port(ports_.back(), address, config, false);
    }

    for (const std::string& address : admin)
    {
      ports_.emplace_back(global_->io);
      any_ssl |= init_port(ports_.back(), address, config, true);
    }

    const bool expect_ssl = !config.auth.private_key_path.empty();
    const std::size_t threads = config.threads;
    if (!any_ssl && expect_ssl)
      MONERO_THROW(lws::error::configuration, "Specified SSL key/cert without specifying https capable REST server");

    workers_.reserve(threads);
    for (std::size_t i = 0; i < threads; ++i)
      workers_.emplace_back(std::bind(&rest_server::run_io, this));
  }

  rest_server::~rest_server() noexcept
  {
    global_->io.stop();
    for (auto& t : workers_)
    {
      if (t.joinable())
        t.join();
    }
  }
} // lws
