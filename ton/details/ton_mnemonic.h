#pragma once

#include "ton/ton_result.h"

namespace Ton::details {

auto RecoverKey(const QString& mnemonic) -> Result<QByteArray>;

[[nodiscard]] std::vector<QString> GenerateBIP39Phrase(const std::vector<QString>& dictionary);

}  // namespace Ton::details
