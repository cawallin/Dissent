#ifndef DISSENT_ANONYMITY_NULL_NONCE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NULL_NONCE_ROUND_H_GUARD

#include "BaseNonceRound.hpp"

namespace Dissent {

namespace Anonymity {
  
namespace Nonce {
  /**
   * A simple wrapper to a round.  Just calls the round that is passed in.
   */
  class NullNonceRound : public BaseNonceRound {
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
      explicit NullNonceRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_round = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~NullNonceRound() {}

      inline virtual QString ToString() const { return "NullNonceRound " + GetRoundId().ToString(); }

    protected:
      /**
       * Called when the NullNonceRound is started
       */
      virtual void OnStart();

    private:
      /**
       * Called when the shuffle finished
       */
      virtual void OnRoundFinished();
  };
}
}
}
#endif
