#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "wire/fwd.h"
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

  struct multisig_register_wallet_request
  {
    std::string wallet_id;
    std::string address;
    std::string context;
    std::uint32_t threshold;
    std::uint32_t total;
    std::vector<std::string> participants;
    std::string status;
    std::uint64_t created_at;
  };

  struct multisig_register_wallet_response
  {
    bool success;
    std::string message;
  };

  struct multisig_list_wallets_request {};

  inline void read_bytes(const wire::reader&, const multisig_list_wallets_request&)
  {}

  struct multisig_wallet_entry
  {
    std::string wallet_id;
    std::string address;
    std::string context;
    std::uint32_t threshold;
    std::uint32_t total;
    std::vector<std::string> participants;
    std::string status;
    std::uint64_t locked_balance;
    std::uint32_t tx_count;
    std::uint64_t created_at;
  };

  struct multisig_list_wallets_response
  {
    std::vector<multisig_wallet_entry> wallets;
  };

  void read_bytes(wire::json_reader&, multisig_register_tx_request&);
  void write_bytes(wire::json_writer&, const multisig_register_tx_response&);
  void read_bytes(wire::json_reader&, multisig_balance_request&);
  void write_bytes(wire::json_writer&, const multisig_balance_response&);
  void read_bytes(wire::json_reader&, multisig_transactions_request&);
  void write_bytes(wire::json_writer&, const multisig_tx_entry&);
  void write_bytes(wire::json_writer&, const multisig_transactions_response&);
  void read_bytes(wire::json_reader&, multisig_register_wallet_request&);
  void write_bytes(wire::json_writer&, const multisig_register_wallet_response&);
  void write_bytes(wire::json_writer&, const multisig_wallet_entry&);
  void write_bytes(wire::json_writer&, const multisig_list_wallets_response&);
}} // lws::rpc
