#include "Connections/Network.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"

#include "NonceRound.hpp"

namespace Dissent {
using Crypto::Hash;
namespace Anonymity {
  NonceRound::NonceRound(const Group &group, 
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data,
      CreateRound create_round) :
    NullNonceRound(group, ident, round_id, network, get_data),
    _state_machine(this)
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["nonce"] = true;
    GetNetwork()->SetHeaders(headers);

    _state_machine.AddState(OFFLINE);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    }
    
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

  void NonceRound::OnStart()
  {
    Round::OnStart();
    _round->Start();
  }

  void NonceRound::OnRoundFinished()
  {
    qDebug() << "NonceRound finished";
    Round::OnStop();
  }

  void NonceRound::InitServer()
  {
    _state_machine.AddState(NONCE_GENERATION);
    _state_machine.AddState(SEND_HASH);
    _state_machine.AddState(WAITING_FOR_HASHES);
    _state_machine.AddState(SEND_N);
    _state_machine.AddState(WAITING_FOR_N);
    _state_machine.AddState(COMBINE);
    _state_machine.AddState(INNER_ROUND);
    _state_machine.AddState(FINISHED);

    _state_machine.AddTransition(OFFLINE, NONCE_GENERATION);
    _state_machine.AddTransition(NONCE_GENERATION, SEND_HASH);
    _state_machine.AddTransition(SEND_HASH, WAITING_FOR_HASHES);
    _state_machine.AddTransition(WAITING_FOR_HASHES, SEND_N);
    _state_machine.AddTransition(SEND_N, WAITING_FOR_N);
    _state_machine.AddTransition(WAITING_FOR_N, COMBINE);
    _state_machine.AddTransition(COMBINE, INNER_ROUND);
    _state_machine.AddTransition(INNER_ROUND, FINISHED);
    
  }
}
}
