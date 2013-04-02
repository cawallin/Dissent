#ifndef DISSENT_ANONYMITY_NONCE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NONCE_ROUND_H_GUARD

#include "Anonymity/RoundStateMachine.hpp"

#include "BaseNonceRound.hpp"

namespace Dissent {

namespace Anonymity {

namespace Nonce {
//  class ShuffleRound;
  /**
   * A simple wrapper to a round.  Just calls the round that is passed in.
   */
  class NonceRound : public BaseNonceRound {
    Q_OBJECT

    Q_ENUMS(States);
    Q_ENUMS(MessageType);
    public:
      friend class RoundStateMachine<NonceRound>;

      enum MessageType {
        MSG_NONCE_HASH = 0,
        MSG_NONCE,
        MSG_SIG
      };

      enum States {
        OFFLINE = 0,
        SEND_HASH,
        WAITING_FOR_HASHES,
        SEND_N,
        WAITING_FOR_N,
        SEND_SIG,
        WAITING_FOR_SIG,
        INNER_ROUND,
        FINISHED
      };

      /**
       * Converts an State into a QString
       * @param state value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mt)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mt);
      }

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id unused
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit NonceRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_round = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~NonceRound() {}

      inline virtual QString ToString() const { return "NonceRound " + GetRoundId().ToString(); }

    
    protected:
      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      virtual void ProcessData(const Id &id, const QByteArray &data)
      {
        _state_machine.ProcessData(id, data);
      }
    
    private:
      /**
       * Called when the shuffle finished
       */
      virtual void OnRoundFinished();
      
      void InitServer();
      /**
       * Holds the round nested inside this round.
       */
      
      /**
       * Called before each state transition
       */
      void BeforeStateTransition() {}

      /**
       * Called after each cycle, i.e., phase conclusion
       */
      bool CycleComplete() {return false;}
      
      /**
       * Safety net, should never be called
       */
      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qDebug() << "Received a message into the empty handle message...";
      }
        
      /**
       * Some transitions don't require any state preparation, they are handled
       * by this
       */
      void EmptyTransitionCallback() {}
      
      RoundStateMachine<NonceRound> _state_machine;
  };

}
}
}
#endif
