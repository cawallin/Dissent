#ifndef DISSENT_ANONYMITY_NULL_NONCE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NULL_NONCE_ROUND_H_GUARD

#include <QSharedPointer>

#include "Messaging/ISink.hpp"
#include "Messaging/ISender.hpp"

#include "BaseBulkRound.hpp"
#include "ShuffleRound.hpp"
#include "Round.hpp"

namespace Dissent {

namespace Anonymity {
  
namespace Nonce {
  class ShuffleRound;
  /**
   * A simple wrapper to a round.  Just calls the round that is passed in.
   */
  class NullNonceRound : public Round, public Messaging::ISink {
    Q_OBJECT

    public:
      typedef Messaging::ISender ISender;

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id unused
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit NullNonceRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_round = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~NullNonceRound() {}

      inline virtual QString ToString() const { return "NullNonceRound " + GetRoundId().ToString(); }

      /**
       * Handle the data coming in from the round and just pass
       * it out immediately
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
                              const QByteArray &data);
    
      virtual const QObject* GetObject();

    protected:
      /**
       * Called when the NullNonceRound is started
       */
      virtual void OnStart();

      /**
       * Pushes the data into the subscribed Sink
       * @param data the data to push
       * @param id the source of the data
       */
      virtual void ProcessData(const Id &id, const QByteArray &data);
  
      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(const Request &notification);



    private:
      /**
       * Called when the shuffle finished
       */
      virtual void OnRoundFinished();
      
      /**
       * Holds the round nested inside this round.
       */
      QSharedPointer<Round> _round;
      
    
    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void RoundFinished() { OnRoundFinished(); }
  };

  template <typename N, typename B, typename S> QSharedPointer<Round> 
          TCreateBulkNonceRound(
      const Round::Group &group, const Round::PrivateIdentity &ident,
      const Connections::Id &round_id,
      QSharedPointer<Connections::Network> network,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<Round> round(new N(group, ident, round_id, network,
          get_data, &TCreateBulkRound<B, S>));
    round->SetSharedPointer(round);
    return round;
  }
  
  template <typename N, typename R> QSharedPointer<Round> 
          TCreateNonceRound(
      const Round::Group &group, const Round::PrivateIdentity &ident,
      const Connections::Id &round_id,
      QSharedPointer<Connections::Network> network,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<Round> round(new N(group, ident, round_id, network,
          get_data, &TCreateRound<R>));
    round->SetSharedPointer(round);
    return round;
  }
}
}
}
#endif
