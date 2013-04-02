#ifndef DISSENT_ANONYMITY_BASE_NONCE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_BASE_NONCE_ROUND_H_GUARD

#include "Anonymity/BaseBulkRound.hpp"
#include "Anonymity/ShuffleRound.hpp"

namespace Dissent {

namespace Anonymity {
  
namespace Nonce {
  /**
   * A simple wrapper to a round.  Just calls the round that is passed in.
   */
  class BaseNonceRound : public Round, public Messaging::ISink {
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
      explicit BaseNonceRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~BaseNonceRound() {}

      inline virtual QString ToString() const { return "BaseNonceRound " + GetRoundId().ToString(); }

      /**
       * Handle the data coming in from the round and just pass
       * it out immediately
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
                              const QByteArray &data);
    
      virtual const QObject* GetObject();

    protected:
      /**
       * Handle a data message from a remote peer; if the message
       * has a key "nonce" that is true, the message goes to the
       * ProcessData of the NonceRound, else the message goes to
       * the inner round.
       * @param notification message from a remote peer
       */
      virtual void IncomingData(const Request &notification);
      
      /**
       * Holds the round nested inside this round.
       */
      QSharedPointer<Round> _round;
   
   private:
      /**
       * Called when the inner round finishes
       */
      virtual void OnRoundFinished() = 0;
      
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
