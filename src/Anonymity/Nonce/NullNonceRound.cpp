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
    Round(group, ident, round_id, network, get_data)
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["nonce"] = true;
    GetNetwork()->SetHeaders(headers);

    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["nonce"] = false;
    net->SetHeaders(headers);

    Id sr_id(Hash().ComputeHash(GetRoundId().GetByteArray()));

    _round = create_round(GetGroup(), GetPrivateIdentity(), sr_id, net,
        get_data);
    _round->SetSink(this);

    QObject::connect(_round.data(), SIGNAL(Finished()),
        this, SLOT(RoundFinished()));
  }

  void NullNonceRound::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }

    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();
    if(!sender) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = sender->GetRemoteId();
    if(!GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << 
        notification.GetFrom()->ToString();
      return;
    }
    
    QVariantHash msg = notification.GetData().toHash();

    qDebug() << "In incoming data! is it a nonce? " << msg.value("nonce", false).toBool();

    if(msg.value("nonce", false).toBool()) {
      ProcessData(id, msg.value("data").toByteArray());
    } else {
      _round->IncomingData(notification);
    }
  }
  
  void NullNonceRound::OnStart()
  {
    Round::OnStart();
    _round->Start();
  }

  void NullNonceRound::ProcessData(const Id &id, const QByteArray &data)
  {
    qDebug() << "in NullNonceRound" << id << data;
  }

  void NullNonceRound::OnRoundFinished()
  {
    qDebug() << "NullNonceRound finished";
    Round::OnStop();
  }

  void NullNonceRound::HandleData(const QSharedPointer<Dissent::Messaging::ISender> &from, const QByteArray
                  &data)
  {
    qDebug() << "Calling handle data! hopefully this works!";
    PushData(from, data);
  }

  const QObject* NullNonceRound::GetObject()
  {
    return this;
  }
}
}
}
