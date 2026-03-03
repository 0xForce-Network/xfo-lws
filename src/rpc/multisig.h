#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "wire/json/fwd.h"

namespace lws { namespace rpc
{
  struct multisig_register_tx_request
  {
    std::string multisig_address;
    std::string tx_hash;
    std::string tx_key;
    std::string context;
  };

  struct multisig_register_tx_response
  {
    bool success;
    std::string message;
    std::uint64_t decoded_amount;
  };

  struct multisig_balance_request
  {
    std::string multisig_address;
  };

  struct multisig_balance_response
  {
    std::string multisig_address;
    std::uint64_t locked_balance;
    std::uint32_t tx_count;
    std::string context;
  };

  struct multisig_transactions_request
  {
    std::string multisig_address;
  };

  struct multisig_tx_entry
  {
    std::string tx_hash;
    std::uint64_t amount;
    std::uint64_t timestamp;
    std::string context;
  };

  struct multisig_transactions_response
  {
    std::string multisig_address;
    std::vector<multisig_tx_entry> transactions;
    std::uint64_t total_locked;
  };

  void read_bytes(wire::json_reader&, multisig_register_tx_request&);
  void write_bytes(wire::json_writer&, const multisig_register_tx_response&);
  void read_bytes(wire::json_reader&, multisig_balance_request&);
  void write_bytes(wire::json_writer&, const multisig_balance_response&);
  void read_bytes(wire::json_reader&, multisig_transactions_request&);
  void write_bytes(wire::json_writer&, const multisig_tx_entry&);
  void write_bytes(wire::json_writer&, const multisig_transactions_response&);
}} // lws::rpc
