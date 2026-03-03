#include "db/multisig_store.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <system_error>

#include "byte_slice.h"
#include "wire/json.h"
#include "wire/vector.h"
#include "wire/wrapper/array.h"
#include "wire/wrappers_impl.h"

namespace lws { namespace db
{
  using max_multisig_txs = wire::max_element_count<32>;
  using max_multisig_addresses = wire::max_element_count<16>;

  void read_bytes(wire::json_reader& source, multisig_tx_record& self)
  {
    wire::object(source,
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(amount),
      WIRE_FIELD(timestamp),
      WIRE_FIELD(context)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_tx_record& self)
  {
    wire::object(dest,
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(amount),
      WIRE_FIELD(timestamp),
      WIRE_FIELD(context)
    );
  }

  void read_bytes(wire::json_reader& source, multisig_address_data& self)
  {
    wire::object(source,
      WIRE_FIELD(address),
      WIRE_FIELD_ARRAY(transactions, max_multisig_txs),
      WIRE_FIELD(total_locked),
      WIRE_FIELD(primary_context)
    );
  }

  void write_bytes(wire::json_writer& dest, const multisig_address_data& self)
  {
    wire::object(dest,
      WIRE_FIELD(address),
      WIRE_FIELD(transactions),
      WIRE_FIELD(total_locked),
      WIRE_FIELD(primary_context)
    );
  }

  namespace
  {
    struct multisig_snapshot
    {
      std::vector<multisig_address_data> addresses;
    };

    void read_bytes(wire::json_reader& source, multisig_snapshot& self)
    {
      wire::object(source, WIRE_FIELD_ARRAY(addresses, max_multisig_addresses));
    }

    void write_bytes(wire::json_writer& dest, const multisig_snapshot& self)
    {
      wire::object(dest, WIRE_FIELD(addresses));
    }

    void save_locked(const std::string& storage_path, const std::map<std::string, multisig_address_data>& data)
    {
      std::filesystem::path path{storage_path};
      const std::filesystem::path dir = path.parent_path();
      if (!dir.empty())
        std::filesystem::create_directories(dir);

      multisig_snapshot snapshot{};
      snapshot.addresses.reserve(data.size());
      for (const auto& entry : data)
        snapshot.addresses.push_back(entry.second);

      epee::byte_slice bytes{};
      const std::error_code error = wire::json::to_bytes(bytes, snapshot);
      if (error)
        throw std::system_error(error);

      std::ofstream out{storage_path, std::ios::binary | std::ios::trunc};
      if (!out)
        throw std::runtime_error{"failed to open multisig storage file for write"};
      out.write(reinterpret_cast<const char*>(bytes.data()), std::streamsize(bytes.size()));
      if (!out.good())
        throw std::runtime_error{"failed to write multisig storage file"};
    }

    void load_locked(const std::string& storage_path, std::map<std::string, multisig_address_data>& data)
    {
      std::ifstream in{storage_path, std::ios::binary};
      if (!in)
        return;

      std::string content{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
      if (content.empty())
        return;

      multisig_snapshot snapshot{};
      const std::error_code error = wire::json::from_bytes(std::move(content), snapshot);
      if (error)
        throw std::system_error(error);

      data.clear();
      for (auto& addr : snapshot.addresses)
        data.emplace(addr.address, std::move(addr));
    }
  } // anonymous

  multisig_store::multisig_store(const std::string& storage_path)
    : data_(), storage_path_(storage_path), mu_()
  {
    load();
  }

  bool multisig_store::register_tx(
    const std::string& address,
    const std::string& tx_hash,
    const std::uint64_t amount,
    const std::string& context
  )
  {
    if (address.empty() || tx_hash.empty())
      return false;

    const std::uint64_t now =
      std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count());

    std::lock_guard<std::mutex> lock{mu_};
    auto& slot = data_[address];
    if (slot.address.empty())
      slot.address = address;

    for (const auto& tx : slot.transactions)
    {
      if (tx.tx_hash == tx_hash)
        return false;
    }

    if (std::numeric_limits<std::uint64_t>::max() - slot.total_locked < amount)
      return false;

    slot.transactions.push_back(multisig_tx_record{tx_hash, amount, now, context});
    slot.total_locked += amount;
    if (slot.primary_context.empty())
      slot.primary_context = context;

    try
    {
      save_locked(storage_path_, data_);
    }
    catch (...)
    {
      return false;
    }

    return true;
  }

  multisig_address_data multisig_store::get_balance(const std::string& address) const
  {
    std::lock_guard<std::mutex> lock{mu_};
    const auto it = data_.find(address);
    if (it == data_.end())
      return multisig_address_data{address, {}, 0, {}};
    return it->second;
  }

  std::vector<multisig_tx_record> multisig_store::get_transactions(const std::string& address) const
  {
    std::lock_guard<std::mutex> lock{mu_};
    const auto it = data_.find(address);
    if (it == data_.end())
      return {};
    return it->second.transactions;
  }

  void multisig_store::save() const
  {
    std::lock_guard<std::mutex> lock{mu_};
    save_locked(storage_path_, data_);
  }

  void multisig_store::load()
  {
    std::lock_guard<std::mutex> lock{mu_};
    load_locked(storage_path_, data_);
  }
}} // lws::db
