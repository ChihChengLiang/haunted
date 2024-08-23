# Haunted: Generic backend to host your phantom-zone

[Phantom-zone](https://github.com/gausslabs/phantom-zone) is a cryptographic library to realize computations of cipher inputs from multiple users.

It takes some extra work to develop interactive applications from phantom-zone. A server is spinned up to take encrypted inputs from the users, perform computations, distribute encrypted outputs back to users, and finally collect and publish decryption materials.

This project aims to address the following application-agnoistc repetitive works, so that app designers can focus on the core application logics.

- To perform the computation on the ciphertexts, the server re-encrypts the ciphertext with a server key, which is derived from key shares collected from users.
- The computation results are encrypted. For a user to view the decrypted content, they needs decryption shares from other users.

Optional Goals: It is desirable to have these features, but I'm not sure if I'm doing them right.

- It's tempting to address the core computation part and include some features in the framework.
  - We want the server to hold some states.
  - We want the server to sign state or computation outputs.
  - Should we model the computation like a blockchain state, tx, and receipts?
- Serialize a struct of FheBools into a vector of FheBools and deserialize it back. This way we can remove the need to re-write the logic of re-encrypting struct memebers.
- JavaScript support. [RiverRuby/pz-web](https://github.com/RiverRuby/pz-web/blob/main/src/ni_hiring.rs) is a good example to look into.

