// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/details/ton_key_destroyer.h"

#include "ton/details/ton_request_sender.h"
#include "ton/details/ton_external.h"
#include "ton/details/ton_storage.h"
#include "ton/ton_state.h"

namespace Ton::details {

KeyDestroyer::KeyDestroyer(not_null<details::RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                           const details::WalletList &existing, KeyType keyType, index_type index, bool useTestNetwork,
                           const Callback<> &done) {
  Expects(index >= 0 && ((keyType == KeyType::Original && index < existing.entries.size()) ||
                         (keyType == KeyType::Ftabi && index < existing.ftabiEntries.size())));

  auto remove = [&](const auto &entry) {
    auto removeFromDatabase = crl::guard(this, [=](const Result<> &) {
      auto copy = existing;
      copy.entries.erase(begin(copy.entries) + index);
      SaveWalletList(db, copy, useTestNetwork, crl::guard(this, done));
    });
    DeletePublicKey(lib, entry.publicKey, entry.secret, std::move(removeFromDatabase));
  };

  switch (keyType) {
    case KeyType::Original: {
      remove(existing.entries[index]);
      return;
    }
    case KeyType::Ftabi: {
      remove(existing.ftabiEntries[index]);
      return;
    }
    default:
      Unexpected("Key type");
  }
}

KeyDestroyer::KeyDestroyer(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                           const Callback<> &done) {
  const auto removeFromDatabase =
      crl::guard(this, [=](const auto &) { SaveWalletList(db, {}, useTestNetwork, crl::guard(this, done)); });
  lib->request(TLDeleteAllKeys()).done(removeFromDatabase).fail(removeFromDatabase).send();
}

}  // namespace Ton::details
