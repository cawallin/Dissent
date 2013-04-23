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
    _state_machine.AddState(PREPARE_INNER_ROUND, PREPARE_IR_MSG, 
        &NonceRound::PrepareInnerRound);
    _state_machine.AddState(INNER_ROUND, -1, 0, &NonceRound::StartInnerRound);
    _state_machine.AddState(FINISHED, -1, 0, &NonceRound::OnFinished);
    
    _state_machine.AddTransition(PREPARE_INNER_ROUND, INNER_ROUND);
    _state_machine.AddTransition(INNER_ROUND, FINISHED);

    _state = QSharedPointer<State>(new State(create_round, get_data, 
        GetGroup().GetSubgroup().Count()));
    
    if(GetGroup().GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    }
    else {
      _state_machine.AddTransition(OFFLINE, PREPARE_INNER_ROUND);
    }
  }

  void NonceRound::OnRoundFinished()
  {
    SetSuccessful(true);
    BaseNonceRound::OnRoundFinished();
    _state_machine.StateComplete();
    qDebug() << "NonceRound finished";
  }

  void NonceRound::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void NonceRound::OnFinished()
  {
    qDebug() << "In OnFinished";
    Round::OnStop();
  }

  void NonceRound::InitServer()
  {
    _state->n_msgs = 0;
    GenerateMyContrib();

    _state_machine.AddState(SEND_HASH, -1, 0, &NonceRound::SendHash);
    _state_machine.AddState(WAITING_FOR_HASHES, MSG_NONCE_HASH, 
        &NonceRound::ReceiveHashes);
    _state_machine.AddState(SEND_N, -1, 0, &NonceRound::SendN);
    _state_machine.AddState(WAITING_FOR_N, MSG_NONCE, &NonceRound::ReceiveNs);
    _state_machine.AddState(SEND_SIG, -1, 0, &NonceRound::SendSig);
    _state_machine.AddState(WAITING_FOR_SIG, MSG_SIG, &NonceRound::ReceiveSig);

    _state_machine.AddTransition(OFFLINE, SEND_HASH);
    _state_machine.AddTransition(SEND_HASH, WAITING_FOR_HASHES);
    _state_machine.AddTransition(WAITING_FOR_HASHES, SEND_N);
    _state_machine.AddTransition(SEND_N, WAITING_FOR_N);
    _state_machine.AddTransition(WAITING_FOR_N, SEND_SIG);
    _state_machine.AddTransition(SEND_SIG, WAITING_FOR_SIG);
    _state_machine.AddTransition(WAITING_FOR_SIG, PREPARE_INNER_ROUND);
  }

  void NonceRound::GenerateMyContrib()
  {
    _state->my_contrib = QByteArray::number(CryptoRandom().GetInt());
    _state->complete_nonce = QByteArray().fill('0', 64);   
    qDebug() << "Generating my contribution: " << _state->my_contrib;
  }

  void NonceRound::SendHash()
  {
    QByteArray hash = Hash().ComputeHash(_state->my_contrib);

    qDebug() << "Sending hash" << hash.toBase64();
    
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << MSG_NONCE_HASH << GetRoundId() << hash;
    
    VerifiableBroadcastToServers(payload);
    _state_machine.StateComplete();
  }

  void NonceRound::SendN()
  {
    qDebug() << "Sending N";

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << MSG_NONCE << GetRoundId() << _state->my_contrib;
   
    qDebug() << "N that is being sent: " << payload.toHex();

    VerifiableBroadcastToServers(payload);
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

    qDebug() << "Receiving hash" << data.toBase64();
    if(_state->n_msgs != GetGroup().GetSubgroup().Count()) {
      return;
    }
    _state->n_msgs = 0;
    _state_machine.StateComplete();
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
    
    if (_state->receivedH[idx] !=  Hash().ComputeHash(data))
    {
      qWarning() << "Hash does not match the value sent";
      return;
    }
    
    _state->receivedN[idx] = data;
    _state->n_msgs++;

    Xor(_state->complete_nonce, data, _state->complete_nonce);
    
    qDebug() << "Complete nonce: " << _state->complete_nonce << "data: " << data;

    qDebug() << GetLocalId().ToString() << "received" << _state->n_msgs << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->n_msgs != GetGroup().GetSubgroup().Count()) {
      return;
    }

    qDebug() << "Complete nonce: " << _state->complete_nonce;

    _state->n_msgs = 0;
    _state_machine.StateComplete();
  }

  void NonceRound::SendSig()
  {
    qDebug() << "Sending signature";
    QByteArray signature = GetPrivateIdentity().GetSigningKey()->
        Sign(_state->complete_nonce); 
    
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << MSG_SIG << GetRoundId()  << signature;

    qDebug() << "Original signature to send" << Hash().ComputeHash(payload);

    VerifiableBroadcastToServers(payload);
      _state_machine.StateComplete();
  }

  void NonceRound::ReceiveSig(const Id &from, QDataStream &stream)
  {
    if(_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;
    qDebug() << "signature: " << signature;
    
    if(!GetGroup().GetKey(from)->Verify(_state->complete_nonce, signature))
    {
      throw QRunTimeError("Signature doesn't match.");
    }

    _state->handled_servers.insert(from);
    _state->signatures[from] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received validation from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->handled_servers.count() == 
            GetGroup().GetSubgroup().Count()) 
    {
      
      QByteArray payload;
      QDataStream stream(&payload, QIODevice::WriteOnly);
      stream << PREPARE_IR_MSG << GetRoundId()  << _state->complete_nonce <<
          _state->signatures;
      
      VerifiableBroadcast(payload);
      _state_machine.StateComplete();
    }
  }

  void NonceRound::PrepareInnerRound(const Id &from, QDataStream &stream)
  {
    if(_state->handled_prepares.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray complete_nonce;
    stream >> complete_nonce;
    
    QHash<Id, QByteArray> signatures;
    stream >> signatures;
    
    
    QHashIterator<Id, QByteArray> it(signatures);
    while (it.hasNext())
    {
      it.next();
      Id id = it.key();
      QByteArray signature = it.value();
      qDebug() << "signature in prepare inner round is " << id << " "<< 
          signature;
      if(id != GetLocalId() &&
          !GetGroup().GetKey(id)->Verify(complete_nonce, signature))
      {
        throw QRunTimeError("Signature doesn't match. ID: " + id.ToString() + 
            " Signature: " + signature);
      }
    }

    if (_state->handled_prepares.size() > 0 && 
          complete_nonce != _state->complete_nonce)
    {
      throw QRunTimeError("Received an incorrect nonce.");
    }

    _state->complete_nonce = complete_nonce;
    _state->handled_prepares.insert(from);
    
    if(_state->handled_prepares.count() == 
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

    Id sr_id(_state->complete_nonce);

    _round = _state->create_round(GetGroup(), GetPrivateIdentity(), 
        sr_id, net, _state->data_cb);
    _round->SetSink(this);
  
    QObject::connect(_round.data(), SIGNAL(Finished()),
        this, SLOT(RoundFinished()));
    
    _round->Start();
    qDebug() << "Starting inner round. Pending messages: " << 
      _pending_round_messages.size();
    foreach(const Request &request, _pending_round_messages){
      _round->IncomingData(request);
      qDebug() << "serving request!";
    }
    _pending_round_messages.clear();
  }
  
  void NonceRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
   // Q_ASSERT(IsServer());

    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      GetNetwork()->Send(pi.GetId(), msg);
    }
  }
  
  void NonceRound::VerifiableBroadcast(const QByteArray &data)
  {
   // Q_ASSERT(IsServer());

    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup()) {
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
