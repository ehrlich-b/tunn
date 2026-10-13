# Device consent

Device code creation records either `publisher` (the default) or `management`
purpose. Clients requesting management access pass `purpose=management` when
creating the code. The browser shows that exact permission and account before
approval. An optional `account_id` binds the request to a selected account; an
unbound request attaches to the verified account at approval.

Publisher codes exchange only for renewable publish/connect credentials.
Management codes exchange only for a 24-hour account credential linked to a
visible device entry. Each successful exchange consumes its code in the same
transaction that creates the credential. Account devices can revoke management
access immediately and stop publisher renewal; publisher access leases expire
within five minutes. Management credentials cannot enroll publishers or become
browser sessions.

Outstanding codes created by earlier versions retain publisher scope. Previously
issued browser sessions and access credentials retain their original expiration;
this change does not extend those credentials. All login nodes and management API
relays must support the new purpose and live-device checks before promotion.
