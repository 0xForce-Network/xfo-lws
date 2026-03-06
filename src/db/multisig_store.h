#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace lws { namespace db
{
  struct multisig_tx_record
  {
    std::string tx_hash;
    std::uint64_t amount;
    std::uint64_t timestamp;
    std::string context;
  };

  struct multisig_wallet_record
  {
    std::string wallet_id;
    std::string address;
    std::string context;         // "miner_stake" | "task_payment"
    std::uint32_t threshold;
    std::uint32_t total;
    std::vector<std::string> participants;
    std::string status;          // "initializing" | "active" | "locked" | "closed"
    std::uint64_t created_at;    // Unix timestamp ms
  };

  struct multisig_address_data
  {
    std::string address;
    std::vector<multisig_tx_record> transactions;
    std::uint64_t total_locked;
    std::string primary_context;
  };

  class multisig_store
  {
    std::map<std::string, multisig_address_data> data_;
    std::vector<multisig_wallet_record> wallets_;
    std::string storage_path_;
    mutable std::mutex mu_;

  public:
    explicit multisig_store(const std::string& storage_path);

    bool register_tx(
      const std::string& address,
      const std::string& tx_hash,
      std::uint64_t amount,
      const std::string& context
    );

    bool register_wallet(const multisig_wallet_record& wallet);

    std::vector<multisig_wallet_record> list_wallets() const;

    multisig_address_data get_balance(const std::string& address) const;

    std::vector<multisig_tx_record> get_transactions(const std::string& address) const;

    void save() const;
    void load();
  };
}} // lws::db
