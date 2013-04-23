#include "Connections/Network.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"

#include "BaseNonceRound.hpp"

namespace Dissent {
using Crypto::Hash;
namespace Anonymity {
namespace Nonce {
  BaseNonceRound::BaseNonceRound(const Group &group, 
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data) :
    Round(group, ident, round_id, network, get_data)
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["nonce"] = true;
    GetNetwork()->SetHeaders(headers);
  }

  void BaseNonceRound::SetInterrupted()
  {
    Round::SetInterrupted();
    if (!_round.isNull()) {
      _round->SetInterrupted();
    }
  }

  void BaseNonceRound::OnStop()
  {
    if (!_round.isNull() && !_round.data()->Stopped()) {
      _round->Stop();
    }
    Round::OnStop();
  }
  
  void BaseNonceRound::IncomingData(const Request &notification)
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

    bool nonce = msg.value("nonce").toBool();
    if(nonce) {
      ProcessData(id, msg.value("data").toByteArray());
    } else {
      if (_round) {
        _round->IncomingData(notification);
      }
      else {
        _pending_round_messages.append(notification);
      }
    }
  }

  void BaseNonceRound::OnRoundFinished()
  {
    SetSuccessful(_round->Successful() && Successful());
  }
  
  void BaseNonceRound::HandleData(const QSharedPointer<Dissent::Messaging::ISender> &from, const QByteArray
                  &data)
  {
    PushData(from, data);
  }

  const QObject* BaseNonceRound::GetObject()
  {
    return this;
  }
  
}
}
}
