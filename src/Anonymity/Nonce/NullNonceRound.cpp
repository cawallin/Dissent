#include "Connections/Network.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"

#include "NullNonceRound.hpp"

namespace Dissent {
using Crypto::Hash;
namespace Anonymity {
namespace Nonce {
  NullNonceRound::NullNonceRound(const Group &group, 
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data,
      CreateRound create_round) :
    BaseNonceRound(group, ident, round_id, network, get_data)
  {
    QSharedPointer<Network> net(GetNetwork()->Clone());
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["nonce"] = false;
    net->SetHeaders(headers);
    
    Id sr_id(Hash().ComputeHash(GetRoundId().GetByteArray()));

    _round = create_round(GetGroup(), GetPrivateIdentity(), sr_id, net,
        get_data);
    _round->SetSink(this);

    QObject::connect(_round.data(), SIGNAL(Finished()),
        this, SLOT(RoundFinished()));
  }
  
  void NullNonceRound::OnStart()
  {
    Round::OnStart();
    RunInnerRound();
  }

  void NullNonceRound::ProcessData(const Id &id, const QByteArray &data)
  {
    qDebug() << "Should not be in Process Data of a " <<
      "NullNonceRound" << id << data;
    Q_ASSERT(true);
  }

  void NullNonceRound::OnRoundFinished()
  {
    BaseNonceRound::OnRoundFinished();
    qDebug() << "NullNonceRound finished.  Inner round exited.";
    Round::OnStop();
  }
}
}
}
