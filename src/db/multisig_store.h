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

    multisig_address_data get_balance(const std::string& address) const;

    std::vector<multisig_tx_record> get_transactions(const std::string& address) const;

    void save() const;
    void load();
  };
}} // lws::db
