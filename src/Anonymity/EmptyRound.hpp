#ifndef DISSENT_ANONYMITY_EMPTY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_EMPTY_ROUND_H_GUARD

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * A simple Dissent exchange.  Just broadcasts everyones message to everyone else
   */
  class EmptyRound : public Round {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id unused
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit EmptyRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~EmptyRound() {}

      inline virtual QString ToString() const { return "EmptyRound " + GetRoundId().ToString(); }

    protected:
      /**
       * Called when the EmptyRound is started
       */
      virtual void OnStart();

      /**
       * Pushes the data into the subscribed Sink
       * @param data the data to push
       * @param id the source of the data
       */
      virtual void ProcessData(const Id &id, const QByteArray &data);

    private:
      /**
       * Don't receive from a remote peer more than once...
       */
      QVector<QByteArray> _received;
      int _n_msgs;
  };
}
}

#endif
