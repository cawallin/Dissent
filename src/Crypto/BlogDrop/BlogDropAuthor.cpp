
#include "BlogDropAuthor.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropAuthor::BlogDropAuthor(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PrivateKey> author_priv) :
    BlogDropClient(params, server_pks, QSharedPointer<const PublicKey>(new PublicKey(author_priv))),
    _author_priv(author_priv)
  {
  }

  bool BlogDropAuthor::GenerateAuthorCiphertext(QByteArray &out,
      const QByteArray &in) const
  {
    if(in.count() > MaxPlaintextLength()) return false;

    QByteArray data = in;
    QList<QByteArray> list;
    for(int element_idx=0; element_idx<GetParameters()->GetNElements(); element_idx++) {
      Plaintext m(GetParameters()); 
      data = m.Encode(data);

      ClientCiphertext c(GetParameters(), GetServerKeys(), GetAuthorKey());
      c.SetAuthorProof(_author_priv, m);
      list.append(c.GetByteArray());
    }

    if(data.count()) return false;

    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;

    return true;
  }

}
}
}