// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/details/ton_parse_state.h"

#include "base/unixtime.h"

#include <QtCore/QDateTime>

namespace Ton::details {
namespace {

[[nodiscard]] PendingTransaction PreparePending(const QString &sender, const TransactionToSend &transaction,
                                                int64 sentUntilSyncTime, const QByteArray &bodyHash) {
  auto result = PendingTransaction();
  result.sentUntilSyncTime = sentUntilSyncTime;
  result.fake.time = base::unixtime::now();
  result.fake.incoming.bodyHash = bodyHash;
  result.fake.incoming.destination = sender;
  auto &outgoing = result.fake.outgoing.emplace_back();
  outgoing.source = sender;
  outgoing.destination = transaction.recipient;
  outgoing.message =
      MessageData{transaction.comment.toUtf8(), QByteArray(),
                  transaction.sendUnencryptedText ? MessageDataType::PlainText : MessageDataType::DecryptedText};
  outgoing.value = transaction.amount;
  return result;
}

constexpr auto kTestRestrictedInitPublicKey = "PuYcgC80F-MUPMI9Y_Gd0NhVrkYm_5_6vXFUqdArH7Uo4Y6P";

}  // namespace

ConfigInfo Parse(const TLoptions_ConfigInfo &data) {
  return data.match([](const TLDoptions_configInfo &data) {
    return ConfigInfo{
        .walletId = data.vdefault_wallet_id().v,
        .restrictedInitPublicKey = tl::utf8(data.vdefault_rwallet_init_public_key())
        //.restrictedInitPublicKey = kTestRestrictedInitPublicKey
        //AssertIsDebug()
    };
  });
}

TransactionId Parse(const TLinternal_TransactionId &data) {
  return data.match([&](const TLDinternal_transactionId &data) {
    auto result = TransactionId();
    result.lt = data.vlt().v;
    result.hash = data.vhash().v;
    return result;
  });
}

RestrictionLimit Parse(const TLrwallet_limit &data) {
  return data.match([&](const TLDrwallet_limit &data) {
    return RestrictionLimit{.seconds = data.vseconds().v, .lockedAmount = data.vvalue().v};
  });
}

AccountState Parse(const TLFullAccountState &data) {
  return data.match([&](const TLDfullAccountState &data) {
    auto result = AccountState();
    result.fullBalance = data.vbalance().v;
    result.lastTransactionId = Parse(data.vlast_transaction_id());
    result.syncTime = data.vsync_utime().v;
    data.vaccount_state().match(
        [&](const TLDrwallet_accountState &data) {
          const auto unlocked = data.vunlocked_balance().v;
          result.lockedBalance = (result.fullBalance > unlocked) ? (result.fullBalance - unlocked) : 0;
          data.vconfig().match([&](const TLDrwallet_config &data) {
            result.restrictionStartAt = data.vstart_at().v;
            result.restrictionLimits =
                ranges::views::all(data.vlimits().v) |
                ranges::views::transform([](const TLrwallet_limit &data) { return Parse(data); }) | ranges::to_vector;
          });
        },
        [](const auto &data) {});
    return result;
  });
}

MessageData Parse(const TLmsg_Data &data) {
  return data.match(
      [&](const TLDmsg_dataText &data) {
        return MessageData{
            .text = tl::utf16(data.vtext()),
            .data = {},
            .type = MessageDataType::PlainText,
        };
      },
      [&](const TLDmsg_dataRaw &data) {
        return MessageData{
            .text = {},
            .data = data.vbody().v,
            .type = MessageDataType::RawBody,
        };
      },
      [&](const TLDmsg_dataEncryptedText &data) {
        return MessageData{.text = {}, .data = data.vtext().v, .type = MessageDataType::EncryptedText};
      },
      [&](const TLDmsg_dataDecryptedText &data) {
        return MessageData{.text = tl::utf16(data.vtext()), .data = {}, .type = MessageDataType::DecryptedText};
      });
}

QString Parse(const TLAccountAddress &data) {
  return data.match([](const TLDaccountAddress &data) { return tl::utf16(data.vaccount_address()); });
}

Message Parse(const TLraw_Message &data) {
  return data.match([&](const TLDraw_message &data) {
    auto result = Message();
    result.bodyHash = data.vbody_hash().v;
    result.created = data.vcreated_lt().v;
    result.source = Parse(data.vsource());
    result.destination = Parse(data.vdestination());
    result.message = Parse(data.vmsg_data());
    result.value = data.vvalue().v;
    result.bounce = data.vbounce().type() == id_boolTrue;
    result.bounced = data.vbounced().type() == id_boolTrue;
    return result;
  });
}

Transaction Parse(const TLraw_Transaction &data) {
  return data.match([&](const TLDraw_transaction &data) {
    auto result = Transaction();
    result.fee = data.vfee().v;
    result.id = Parse(data.vtransaction_id());
    result.incoming = Parse(data.vin_msg());
    result.outgoing = ranges::views::all(data.vout_msgs().v) |
                      ranges::views::transform([](const TLraw_Message &data) { return Parse(data); }) |
                      ranges::to_vector;
    result.otherFee = data.vother_fee().v;
    result.storageFee = data.vstorage_fee().v;
    result.time = data.vutime().v;
    result.aborted = data.vaborted().type() == id_boolTrue;
    return result;
  });
}

TransactionsSlice Parse(const TLraw_Transactions &data) {
  return data.match([&](const TLDraw_transactions &data) {
    auto result = TransactionsSlice();
    result.previousId = Parse(data.vprevious_transaction_id());
    result.list = ranges::views::all(data.vtransactions().v) |
                  ranges::views::transform([](const TLraw_Transaction &data) { return Parse(data); }) |
                  ranges::to_vector;
    return result;
  });
}

PendingTransaction Parse(const TLquery_Info &data, const QString &sender, const TransactionToSend &transaction) {
  return data.match([&](const TLDquery_info &data) {
    return PreparePending(sender, transaction, data.vvalid_until().v, data.vbody_hash().v);
  });
}

TransactionFees Parse(const TLFees &data) {
  return data.match([&](const TLDfees &data) {
    auto result = TransactionFees();
    result.inForward = data.vin_fwd_fee().v;
    result.gas = data.vgas_fee().v;
    result.storage = data.vstorage_fee().v;
    result.forward = data.vfwd_fee().v;
    return result;
  });
}

TransactionCheckResult Parse(const TLquery_Fees &data) {
  return data.match([&](const TLDquery_fees &data) {
    auto result = TransactionCheckResult();
    result.sourceFees = Parse(data.vsource_fees());
    result.destinationFees = ranges::views::all(data.vdestination_fees().v) |
                             ranges::views::transform([](const TLFees &data) { return Parse(data); }) |
                             ranges::to_vector;
    return result;
  });
}

std::vector<QString> Parse(const TLExportedKey &data) {
  return data.match([&](const TLDexportedKey &data) {
    return ranges::views::all(data.vword_list().v) |
           ranges::views::transform([](const TLsecureString &data) { return tl::utf16(data.v); }) | ranges::to_vector;
  });
}

SyncState Parse(const TLSyncState &data) {
  return data.match([&](const TLDsyncStateDone &data) { return SyncState(); },
                    [&](const TLDsyncStateInProgress &data) {
                      return SyncState{data.vfrom_seqno().v, data.vto_seqno().v, data.vcurrent_seqno().v};
                    });
}

Update Parse(const TLUpdate &data) {
  return data.match([&](const TLDupdateSyncState &data) -> Update { return {Parse(data.vsync_state())}; },
                    [&](const TLDupdateSendLiteServerQuery &data) -> Update {
                      return {LiteServerQuery{data.vid().v, data.vdata().v}};
                    });
}

TLmsg_DataEncryptedArray MsgDataArrayFromEncrypted(const QVector<EncryptedText> &data) {
  auto list = QVector<TLmsg_dataEncrypted>();
  list.reserve(data.size());
  for (const auto &text : data) {
    list.push_back(tl_msg_dataEncrypted(tl_accountAddress(tl_string(text.source)),
                                        tl_msg_dataEncryptedText(tl_bytes(text.bytes))));
  }
  return tl_msg_dataEncryptedArray(tl_vector(list));
}

QVector<DecryptedText> MsgDataArrayToDecrypted(const TLmsg_DataDecryptedArray &data) {
  return data.match([&](const TLDmsg_dataDecryptedArray &data) {
    auto result = QVector<DecryptedText>();
    const auto &list = data.velements().v;
    result.reserve(list.size());
    for (const auto &element : list) {
      element.match([&](const TLDmsg_dataDecrypted &data) {
        const auto proof = data.vproof().v;
        data.vdata().match(
            [&](const TLDmsg_dataDecryptedText &data) {
              result.push_back({tl::utf16(data.vtext()), proof});
            },
            [&](const auto &) {
              result.push_back({QString(), proof});
            });
      });
    }
    return result;
  });
}

QVector<EncryptedText> CollectEncryptedTexts(const std::vector<Transaction> &data) {
  auto result = QVector<EncryptedText>();
  result.reserve(data.size());
  const auto add = [&](const Message &data) {
    if (!data.message.data.isEmpty()) {
      result.push_back({data.message.data, data.source});
    }
  };
  for (const auto &transaction : data) {
    add(transaction.incoming);
    for (const auto &out : transaction.outgoing) {
      add(out);
    }
  }
  return result;
}

std::vector<Transaction> AddDecryptedTexts(std::vector<Transaction> parsed, const QVector<EncryptedText> &encrypted,
                                           const QVector<DecryptedText> &decrypted) {
  Expects(encrypted.size() == decrypted.size());

  if (encrypted.isEmpty()) {
    return parsed;
  }
  const auto decrypt = [&](Message &message) {
    const auto &was = message.message.data;
    if (was.isEmpty() || message.message.type == MessageDataType::RawBody) {
      return;
    }
    const auto i = ranges::find(encrypted, was, &EncryptedText::bytes);
    if (i != encrypted.end()) {
      message.message.text = decrypted[i - encrypted.begin()].text;
      message.message.type = MessageDataType::DecryptedText;
    }
  };
  for (auto &transaction : parsed) {
    decrypt(transaction.incoming);
    for (auto &out : transaction.outgoing) {
      decrypt(out);
    }
  }
  return parsed;
}

}  // namespace Ton::details
