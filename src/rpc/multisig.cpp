#include "rpc/multisig.h"

#include "wire/json.h"
#include "wire/vector.h"
#include "wire/wrapper/array.h"
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
}} // lws::rpc
