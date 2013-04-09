#include "Connections/Network.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/ISender.hpp"
#include "Utils/QRunTimeError.hpp"

#include "NonceRound.hpp"

namespace Dissent {
using Crypto::CryptoRandom;
using Crypto::Hash;
using Identity::PublicIdentity;
using Utils::QRunTimeError;
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

    //_state = QSharedPointer<State>(new State());
    
    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer(create_round, get_data);
    }
  }

  void NonceRound::OnRoundFinished()
  {
    qDebug() << "NonceRound finished";
    _state_machine.StateComplete();
    setSuccessful(_round->Successful() && Successful());
    Round::OnStop();
  }

  void NonceRound::InitServer(CreateRound create_round, GetDataCallback 
    &data_cb)
  {
    _state->create_round = create_round;
    _state->data_cb = data_cb;

    GenerateMyContrib();

    _state_machine.AddState(SEND_HASH, -1, 0, &NonceRound::SendHash);
    _state_machine.AddState(WAITING_FOR_HASHES, -1, 
        &NonceRound::ReceiveHashes);
    _state_machine.AddState(SEND_N, -1, 0, &NonceRound::SendN);
    _state_machine.AddState(WAITING_FOR_N, -1, &NonceRound::ReceiveNs);
    _state_machine.AddState(SEND_SIG, -1, 0, &NonceRound::SendSig);
    _state_machine.AddState(WAITING_FOR_SIG, -1, &NonceRound::ReceiveSig);
    _state_machine.AddState(INNER_ROUND, -1, 0, 
        &NonceRound::StartInnerRound);
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

  void NonceRound::GenerateMyContrib()
  {
    _state->my_contrib = CryptoRandom().GetInt();
  }

  void NonceRound::SendHash()
  {
    VerifiableBroadcastToServers(Hash().ComputeHash(
      QByteArray::number(_state->my_contrib)));
    _state_machine.StateComplete();
  }

  void NonceRound::SendN()
  {
    VerifiableBroadcastToServers(QByteArray::number(_state->my_contrib));
    _state_machine.StateComplete();
  }

  void NonceRound::ReceiveHashes(const Id &id, QDataStream &stream)
  {
    const int idx = GetGroup().GetSubgroup().GetIndex(id);

    if(!_state->receivedH[idx].isEmpty()) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }

    QByteArray data;
    stream >> data;
    
    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" <<
        id.ToString();
    }

    _state->receivedH[idx] = data;
    _state->n_msgs++;

    qDebug() << GetLocalId().ToString() << "received" << _state->n_msgs << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->n_msgs != GetGroup().GetSubgroup().Count()) {
      return;
    }
    _state_machine.StateComplete();
    _state->n_msgs = 0;
  }

  void NonceRound::ReceiveNs(const Id &id, QDataStream &stream)
  {
  
    const int idx = GetGroup().GetSubgroup().GetIndex(id);

    if(!_state->receivedN[idx].isEmpty()) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }

    QByteArray data;
    stream >> data;
    
    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" <<
        id.ToString();
    }

    if (Hash().ComputeHash(_state->receivedH[idx]) != 
       Hash().ComputeHash(data))
    {
      qWarning() << "Hash does not match the value sent";
      return;
    }
    
    _state->receivedN[idx] = data;
    _state->n_msgs++;

    QByteArray complete_array;
    Xor(complete_array, data, QByteArray::number(_state->complete_nonce));

    _state->complete_nonce = complete_array.toInt();

    qDebug() << GetLocalId().ToString() << "received" << _state->n_msgs << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->n_msgs != GetGroup().GetSubgroup().Count()) {
      return;
    }
    _state_machine.StateComplete();
    _state->n_msgs = 0;
  }

  void NonceRound::SendSig()
  {
    QByteArray signature = GetPrivateIdentity().GetSigningKey()->
        Sign(QByteArray::number(_state->complete_nonce)); 
    
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << MSG_SIG << GetRoundId() << _state_machine.GetPhase()
        << signature;

    VerifiableBroadcastToServers(payload);
  }

  void NonceRound::ReceiveSig(const Id &from, QDataStream &stream)
  {
  
    if(_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetSubgroup().GetKey(from)->
        Verify(QByteArray::number(_state->complete_nonce), signature))
    {
      throw QRunTimeError("Signature doesn't match.");
    }

    _state->handled_servers.insert(from);
    _state->signatures[GetGroup().GetSubgroup().GetIndex(from)] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received validation from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->handled_servers.count() == 
            GetGroup().GetSubgroup().Count()) 
    {
      _state_machine.StateComplete();
    }
  }

  void NonceRound::StartInnerRound()
  {
    QSharedPointer<Network> net(GetNetwork()->Clone());
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["nonce"] = false;
    net->SetHeaders(headers);

    Id sr_id(QByteArray::number(_state->complete_nonce));

    _round = _state->create_round(GetGroup(), GetPrivateIdentity(), sr_id, net,
        _state->data_cb);
    _round->SetSink(this);
  
    QObject::connect(_round.data(), SIGNAL(Finished()),
        this, SLOT(RoundFinished()));
  }

  void NonceRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
   // Q_ASSERT(IsServer());

    QByteArray msg = data; //+ GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      GetNetwork()->Send(pi.GetId(), msg);
    }
  }
  
  void NonceRound::Xor(QByteArray &dst, const QByteArray &t1,
      const QByteArray &t2)
  {
    /// @todo use qint64 or qint32 depending on architecture
    int count = std::min(dst.size(), t1.size());
    count = std::min(count, t2.size());

    for(int idx = 0; idx < count; idx++) {
      dst[idx] = t1[idx] ^ t2[idx];
    }
  }
}
}
}
