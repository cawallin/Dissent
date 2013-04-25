#include "Connections/Network.hpp"

#include "EmptyRound.hpp"

namespace Dissent {
namespace Anonymity {
  EmptyRound::EmptyRound(const Group &group, const PrivateIdentity &ident,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data) :
    Round(group, ident, round_id, network, get_data),
    _received(GetGroup().Count()),
    _n_msgs(0)
  {
  }

  void EmptyRound::OnStart()
  {
    qDebug() << "Starting empty round.";
    Round::OnStart();
    QPair<QByteArray, bool> data = GetData(1024);
    GetNetwork()->Broadcast(data.first);
    SetSuccessful(true);
    Stop("Round successfully finished.");
  }

  void EmptyRound::ProcessData(const Id &id, const QByteArray &data)
  {
    qDebug() << id << data << "go to processdata!";
  }
}
}
