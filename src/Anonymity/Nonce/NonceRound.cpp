#include "Connections/Network.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"

#include "NonceRound.hpp"

namespace Dissent {
using Crypto::Hash;
namespace Anonymity {
namespace Nonce {
  NonceRound::NonceRound(const Group &group, 
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data,
      CreateRound create_round) :
    BaseNonceRound(group, ident, round_id, network, get_data),
    _state_machine(this)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    }
    
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

  void NonceRound::OnRoundFinished()
  {
    qDebug() << "NonceRound finished";
    Round::OnStop();
  }

  void NonceRound::InitServer()
  {
    _state_machine.AddState(SEND_HASH);
    _state_machine.AddState(WAITING_FOR_HASHES);
    _state_machine.AddState(SEND_N);
    _state_machine.AddState(WAITING_FOR_N);
    _state_machine.AddState(SEND_SIG);
    _state_machine.AddState(WAITING_FOR_SIG);
    _state_machine.AddState(INNER_ROUND);
    _state_machine.AddState(FINISHED);

    _state_machine.AddTransition(OFFLINE, SEND_HASH);
    _state_machine.AddTransition(SEND_HASH, WAITING_FOR_HASHES);
    _state_machine.AddTransition(WAITING_FOR_HASHES, SEND_N);
    _state_machine.AddTransition(SEND_N, WAITING_FOR_N);
    _state_machine.AddTransition(WAITING_FOR_N, SEND_SIG);
    _state_machine.AddTransition(SEND_SIG, WAITING_FOR_SIG);
    _state_machine.AddTransition(WAITING_FOR_SIG, INNER_ROUND);
    _state_machine.AddTransition(INNER_ROUND, FINISHED);
    
  }
}
}
}
