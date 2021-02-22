// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_account_viewer.h"

#include "ton/ton_wallet.h"
#include "ton/details/ton_parse_state.h"

namespace Ton {
namespace {

using namespace details;

constexpr auto kDefaultRefreshEach = 60 * crl::time(1000);

}  // namespace

AccountViewer::AccountViewer(not_null<Wallet *> wallet, QByteArray publicKey, QString address,
                             rpl::producer<WalletViewerState> state)
    : _wallet(wallet)
    , _publicKey(std::move(publicKey))
    , _address(std::move(address))
    , _state(std::move(state))
    , _refreshEach(kDefaultRefreshEach) {
}

rpl::producer<WalletViewerState> AccountViewer::state() const {
  return rpl::duplicate(_state);
}

rpl::producer<Result<std::pair<Symbol, LoadedSlice>>> AccountViewer::loaded() const {
  return _loadedResults.events();
}

rpl::producer<not_null<const QString *>> AccountViewer::tokenWalletDeployed() const {
  return _tokenWalletDeployed.events();
}

rpl::producer<not_null<const QString *>> AccountViewer::dePoolAdded() const {
  return _dePoolAdded.events();
}

void AccountViewer::refreshNow(Callback<> done) {
  _refreshNowRequests.fire(std::move(done));
}

rpl::producer<Callback<>> AccountViewer::refreshNowRequests() const {
  return _refreshNowRequests.events();
}

void AccountViewer::setRefreshEach(crl::time delay) {
  _refreshEach = delay;
}

crl::time AccountViewer::refreshEach() const {
  return _refreshEach.current();
}

rpl::producer<crl::time> AccountViewer::refreshEachValue() const {
  return _refreshEach.value();
}

void AccountViewer::preloadSlice(const TransactionId &lastId) {
  if (_preloadIds.contains(lastId)) {
    return;
  }
  _preloadIds.emplace(lastId);
  const auto done = [=](Result<TransactionsSlice> result) {
    if (!result) {
      _loadedResults.fire(std::move(result.error()));
      return;
    }
    const auto previousId = result->previousId;
    const auto done = [=](Result<std::vector<Transaction>> &&result) {
      if (!result) {
        _loadedResults.fire(std::move(result.error()));
        return;
      }
      _preloadIds.remove(lastId);

      auto addDePool = [&](const QString &address) {
        if (_knownDePools.insert(address).second) {
          _dePoolAdded.fire(&address);
        }
      };

      for (const auto &transaction : result.value()) {
        v::match(
            transaction.additional,
            [&](const Ton::TokenWalletDeployed &event) { _tokenWalletDeployed.fire_copy(&event.rootTokenContract); },
            [&](const Ton::DePoolOrdinaryStakeTransaction &) {
              for (const auto &out : transaction.outgoing) {
                addDePool(out.destination);
                break;
              }
            },
            [&](const Ton::DePoolOnRoundCompleteTransaction &) {
              if (!transaction.incoming.source.isEmpty()) {
                addDePool(transaction.incoming.source);
              }
            },
            [](auto &&) {});
      }
      _loadedResults.fire(
          std::make_pair(Ton::Symbol::ton(), LoadedSlice{lastId, TransactionsSlice{std::move(*result), previousId}}));
    };
    _wallet->trySilentDecrypt(_publicKey, std::move(result->list), done);
  };
  _wallet->requestTransactions(_address, lastId, crl::guard(this, done));
}

void AccountViewer::preloadTokenSlice(const Symbol &symbol, const QString &tokenWalletAddress,
                                      const TransactionId &lastId) {
  if (_preloadIds.contains(lastId)) {
    return;
  }
  _preloadIds.emplace(lastId);
  const auto done = [this, symbol = symbol, lastId = lastId](Result<TransactionsSlice> result) {
    if (!result) {
      _loadedResults.fire(std::move(result.error()));
      return;
    }
    _preloadIds.remove(lastId);
    _loadedResults.fire(std::make_pair(symbol, LoadedSlice{lastId, std::move(result.value())}));
  };
  _wallet->requestTransactions(tokenWalletAddress, lastId, crl::guard(this, done));
}

}  // namespace Ton
