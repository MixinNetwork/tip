# TIP

TIP (Throttled Identity PIN) is a decentralized key custodian, which allows human to get both secure and convenient access to decentralized applications.

## Workflow

TIP is secured by three parties with different roles.

The three parties are User(U), Trusted Account Manager(M) and Trusted Distributed Ledger(L). Three parties cooperate together to avoid single point failure in all roles, to be both decentralized secure and convenient.

User is typically a true human, or some bot code, and they are not connected with any specific devices. The duty of User is remembering their 6 digit PIN securely, easy enough for them.

Trusted Account Manager connects User with some secret seeds, and the Manager usually uses SMS verification to make it easy to use for a normal User.

Trusted Distributed Ledger is a public distributed network, and manages multisig keys for User. User uses PIN and seeds from M to make a signing request to the Ledger and get a signature.
