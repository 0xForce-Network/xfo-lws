#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "db/data.h"
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

  struct multisig_kex_submit_request
  {
    std::string wallet_id;
    std::string context;
    std::string participant;
    std::string multisig_info;
    std::uint32_t round;
    std::uint32_t threshold;
    std::uint32_t total;
    std::uint64_t created_at;
    std::string auth_token;
  };

  struct multisig_kex_response
  {
    bool success;
    std::string wallet_id;
    std::string state;
    std::uint32_t threshold;
    std::uint32_t total;
    std::vector<std::string> participants;
    std::vector<std::string> peer_multisig_info;
    std::string message;
    std::uint64_t created_at;
  };

  struct multisig_kex_status_request
  {
    std::string wallet_id;
    std::string context;
  };

  struct multisig_kex_status_response
  {
    bool success;
    std::string wallet_id;
    std::string context;
    std::string state;
    std::uint32_t threshold;
    std::uint32_t total;
    std::vector<std::string> participants;
    std::vector<std::string> submitted_participants;
    std::vector<std::string> missing_participants;
    std::uint32_t round;
    std::string address;
    std::string message;
    std::uint64_t created_at;
    std::uint64_t updated_at;
  };

  struct multisig_kex_finalize_request
  {
    std::string wallet_id;
    std::string address;
    std::string context;
    std::string status;
  };

  struct multisig_kex_finalize_response
  {
    bool success;
    std::string message;
  };

  struct multisig_txset_register_request
  {
    lws::db::account_address address;
    crypto::secret_key key;
    std::string wallet_id;
    std::string multisig_address;
    std::string tx_data_hex;
    std::string miner_address;
    std::string purpose;
    std::string unstake_amount;
    std::string current_stake;
    std::string remaining_stake;
    std::uint64_t unlock_height;
  };

  struct multisig_txset_register_response
  {
    bool success;
    std::string txset_id;
    std::string state;
    std::string error;
  };

  struct multisig_txset_signature_request
  {
    lws::db::account_address address;
    crypto::secret_key key;
    std::string wallet_id;
    std::string txset_id;
    std::string multisig_address;
    std::string signer_address;
    std::string signer_role;
    std::string signed_tx_data_hex;
    std::vector<std::string> tx_hash_list;
  };

  struct multisig_txset_signature_response
  {
    bool success;
    std::string txset_id;
    std::string state;
    std::uint32_t collected_signatures;
    std::uint32_t required_signatures;
    std::string submitted_tx_hash;
    std::string error;
  };

  struct multisig_txset_submit_request
  {
    lws::db::account_address address;
    crypto::secret_key key;
    std::string wallet_id;
    std::string txset_id;
    std::string multisig_address;
  };

  struct multisig_txset_submit_response
  {
    bool success;
    std::string tx_hash;
    std::string state;
    std::string error;
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
  void read_bytes(wire::json_reader&, multisig_kex_submit_request&);
  void write_bytes(wire::json_writer&, const multisig_kex_response&);
  void read_bytes(wire::json_reader&, multisig_kex_status_request&);
  void write_bytes(wire::json_writer&, const multisig_kex_status_response&);
  void read_bytes(wire::json_reader&, multisig_kex_finalize_request&);
  void write_bytes(wire::json_writer&, const multisig_kex_finalize_response&);
  void read_bytes(wire::json_reader&, multisig_txset_register_request&);
  void write_bytes(wire::json_writer&, const multisig_txset_register_response&);
  void read_bytes(wire::json_reader&, multisig_txset_signature_request&);
  void write_bytes(wire::json_writer&, const multisig_txset_signature_response&);
  void read_bytes(wire::json_reader&, multisig_txset_submit_request&);
  void write_bytes(wire::json_writer&, const multisig_txset_submit_response&);
}} // lws::rpc
