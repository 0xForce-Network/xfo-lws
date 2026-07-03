#include "rpc/multisig.h"

#include <functional>

#include "db/string.h"
#include "wire/adapted/crypto.h"
#include "wire/json.h"
#include "wire/vector.h"
#include "wire/wrapper/array.h"
#include "wire/wrapper/defaulted.h"
#include "wire/wrappers_impl.h"

namespace lws { namespace rpc
{
  void read_bytes(wire::json_reader& source, multisig_register_tx_request& self)
  {
    wire::object(source,
      WIRE_FIELD(multisig_address),
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(tx_key),
      WIRE_FIELD(context)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_register_tx_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(message),
      WIRE_FIELD(decoded_amount)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_balance_request& self)
  {
    wire::object(source, WIRE_FIELD(multisig_address));
  }

  void write_bytes(wire::json_writer& dest, const multisig_balance_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(multisig_address),
      WIRE_FIELD(locked_balance),
      WIRE_FIELD(tx_count),
      WIRE_FIELD(context)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_transactions_request& self)
  {
    wire::object(source, WIRE_FIELD(multisig_address));
  }

  void write_bytes(wire::json_writer& dest, const multisig_tx_entry& self)
  {
    wire::object(dest,
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(amount),
      WIRE_FIELD(timestamp),
      WIRE_FIELD(context)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_transactions_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(multisig_address),
      WIRE_FIELD(transactions),
      WIRE_FIELD(total_locked)
    );
  }

  using max_rpc_participants = wire::max_element_count<8>;

  void read_bytes(wire::json_reader& source, multisig_register_wallet_request& self)
  {
    wire::object(source,
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(address),
      WIRE_FIELD(context),
      WIRE_FIELD(threshold),
      WIRE_FIELD(total),
      WIRE_FIELD_ARRAY(participants, max_rpc_participants),
      WIRE_FIELD(status),
      WIRE_FIELD(created_at)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_register_wallet_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(message)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_wallet_entry& self)
  {
    wire::object(dest,
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(address),
      WIRE_FIELD(context),
      WIRE_FIELD(threshold),
      WIRE_FIELD(total),
      WIRE_FIELD(participants),
      WIRE_FIELD(status),
      WIRE_FIELD(locked_balance),
      WIRE_FIELD(tx_count),
      WIRE_FIELD(created_at)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_list_wallets_response& self)
  {
    wire::object(dest, WIRE_FIELD(wallets));
  }

  using max_peer_multisig_info = wire::max_element_count<8>;

  void read_bytes(wire::json_reader& source, multisig_kex_submit_request& self)
  {
    wire::object(source,
      WIRE_FIELD_DEFAULTED(wallet_id, std::string{}),
      WIRE_FIELD(context),
      WIRE_FIELD(participant),
      WIRE_FIELD(multisig_info),
      WIRE_FIELD_DEFAULTED(round, std::uint32_t(1)),
      WIRE_FIELD_DEFAULTED(threshold, std::uint32_t(2)),
      WIRE_FIELD_DEFAULTED(total, std::uint32_t(3)),
      WIRE_FIELD_DEFAULTED(created_at, std::uint64_t(0)),
      WIRE_FIELD_DEFAULTED(auth_token, std::string{})
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_kex_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(state),
      WIRE_FIELD(threshold),
      WIRE_FIELD(total),
      WIRE_FIELD(participants),
      WIRE_FIELD(peer_multisig_info),
      WIRE_FIELD(message),
      WIRE_FIELD(created_at)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_kex_status_request& self)
  {
    wire::object(source,
      WIRE_FIELD(wallet_id),
      WIRE_FIELD_DEFAULTED(context, std::string{})
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_kex_status_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(context),
      WIRE_FIELD(state),
      WIRE_FIELD(threshold),
      WIRE_FIELD(total),
      WIRE_FIELD(participants),
      WIRE_FIELD(submitted_participants),
      WIRE_FIELD(missing_participants),
      WIRE_FIELD(round),
      WIRE_FIELD(address),
      WIRE_FIELD(message),
      WIRE_FIELD(created_at),
      WIRE_FIELD(updated_at)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_kex_finalize_request& self)
  {
    wire::object(source,
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(address),
      WIRE_FIELD(context),
      WIRE_FIELD_DEFAULTED(status, std::string{"active"})
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_kex_finalize_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(message)
    );
  }

  using max_txset_hashes = wire::max_element_count<8>;

  void read_bytes(wire::json_reader& source, multisig_txset_register_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.key)))),
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(multisig_address),
      WIRE_FIELD(tx_data_hex),
      WIRE_FIELD(miner_address),
      WIRE_FIELD(purpose),
      WIRE_FIELD_DEFAULTED(unstake_amount, std::string{}),
      WIRE_FIELD_DEFAULTED(current_stake, std::string{}),
      WIRE_FIELD_DEFAULTED(remaining_stake, std::string{}),
      WIRE_FIELD_DEFAULTED(unlock_height, std::uint64_t(0))
    );
    expect<db::account_address> parsed = db::address_string(address);
    if (!parsed)
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "invalid Monero address format - " << parsed.error());
    self.address = std::move(*parsed);
  }

  void write_bytes(wire::json_writer& dest, const multisig_txset_register_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(txset_id),
      WIRE_FIELD(state),
      WIRE_FIELD(error)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_txset_signature_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.key)))),
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(txset_id),
      WIRE_FIELD(multisig_address),
      WIRE_FIELD(signer_address),
      WIRE_FIELD(signer_role),
      WIRE_FIELD(signed_tx_data_hex),
      wire::optional_field("tx_hash_list", wire::array<max_txset_hashes>(std::ref(self.tx_hash_list)))
    );
    expect<db::account_address> parsed = db::address_string(address);
    if (!parsed)
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "invalid Monero address format - " << parsed.error());
    self.address = std::move(*parsed);
  }

  void write_bytes(wire::json_writer& dest, const multisig_txset_signature_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(txset_id),
      WIRE_FIELD(state),
      WIRE_FIELD(collected_signatures),
      WIRE_FIELD(required_signatures),
      WIRE_FIELD(submitted_tx_hash),
      WIRE_FIELD(error)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_txset_submit_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.key)))),
      WIRE_FIELD(wallet_id),
      WIRE_FIELD(txset_id),
      WIRE_FIELD(multisig_address)
    );
    expect<db::account_address> parsed = db::address_string(address);
    if (!parsed)
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "invalid Monero address format - " << parsed.error());
    self.address = std::move(*parsed);
  }

  void write_bytes(wire::json_writer& dest, const multisig_txset_submit_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(success),
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(state),
      WIRE_FIELD(error)
    );
  }
}} // lws::rpc
