-- Synthetic six-account database produced by the unmodified 110485c seed reproduction.
BEGIN TRANSACTION;
CREATE TABLE account_emails (
		account_id TEXT NOT NULL,
		email TEXT PRIMARY KEY,
		verified_via TEXT NOT NULL,
		added_at INTEGER NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
INSERT INTO "account_emails" VALUES('77b95d49-e1e4-40cb-a7f6-4a8ae691db1f','operator@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('6a023117-f450-47e3-a714-1e9406c8597e','manual@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('c0dd4616-9df5-4a08-b141-2a84dcd527b2','stripe-paid@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('f12732ef-80a0-48dd-b844-6a01d58d2a62','sequenced@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('b6ce95f0-c2b1-44b9-a9d8-57e470b30250','fixture-reviewed@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('7cc444ea-65d4-4992-ac32-12932e834672','merged@example.invalid','fixture',1791733828);
INSERT INTO "account_emails" VALUES('7cc444ea-65d4-4992-ac32-12932e834672','alias@example.invalid','fixture',1791733828);
CREATE TABLE account_merges (
		old_id TEXT PRIMARY KEY,
		account_id TEXT NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
INSERT INTO "account_merges" VALUES('d74adf46-591e-4a60-aefd-fd730631a7dc','7cc444ea-65d4-4992-ac32-12932e834672');
CREATE TABLE account_usage (
		account_id TEXT NOT NULL,
		month TEXT NOT NULL,
		bytes_used INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (account_id, month),
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
INSERT INTO "account_usage" VALUES('77b95d49-e1e4-40cb-a7f6-4a8ae691db1f','2026-10',12345);
INSERT INTO "account_usage" VALUES('6a023117-f450-47e3-a714-1e9406c8597e','2026-10',12345);
INSERT INTO "account_usage" VALUES('c0dd4616-9df5-4a08-b141-2a84dcd527b2','2026-10',12345);
INSERT INTO "account_usage" VALUES('f12732ef-80a0-48dd-b844-6a01d58d2a62','2026-10',12345);
INSERT INTO "account_usage" VALUES('b6ce95f0-c2b1-44b9-a9d8-57e470b30250','2026-10',12345);
INSERT INTO "account_usage" VALUES('7cc444ea-65d4-4992-ac32-12932e834672','2026-10',12345);
CREATE TABLE accounts (
		id TEXT PRIMARY KEY,
		primary_email TEXT NOT NULL,
		plan TEXT NOT NULL DEFAULT 'free',
		created_at INTEGER NOT NULL
	);
INSERT INTO "accounts" VALUES('77b95d49-e1e4-40cb-a7f6-4a8ae691db1f','operator@example.invalid','pro',1791733828);
INSERT INTO "accounts" VALUES('6a023117-f450-47e3-a714-1e9406c8597e','manual@example.invalid','pro',1791733828);
INSERT INTO "accounts" VALUES('c0dd4616-9df5-4a08-b141-2a84dcd527b2','stripe-paid@example.invalid','pro',1791733828);
INSERT INTO "accounts" VALUES('f12732ef-80a0-48dd-b844-6a01d58d2a62','sequenced@example.invalid','pro',1791733828);
INSERT INTO "accounts" VALUES('b6ce95f0-c2b1-44b9-a9d8-57e470b30250','fixture-reviewed@example.invalid','pro',1791733828);
INSERT INTO "accounts" VALUES('7cc444ea-65d4-4992-ac32-12932e834672','merged@example.invalid','pro',1791733828);
CREATE TABLE device_codes (
		code TEXT PRIMARY KEY,
		user_code TEXT UNIQUE NOT NULL,
		expires_at INTEGER NOT NULL,
		authorized INTEGER NOT NULL DEFAULT 0,
		email TEXT
	);
CREATE TABLE ops_account_audit (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL, original_account_id TEXT NOT NULL, version INTEGER NOT NULL,
 previous_state TEXT NOT NULL, state TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, changed_at TEXT NOT NULL
);
INSERT INTO "ops_account_audit" VALUES('506b1aa6-4b28-424c-b0e4-e3cc1930f6cb','77b95d49-e1e4-40cb-a7f6-4a8ae691db1f','77b95d49-e1e4-40cb-a7f6-4a8ae691db1f',1,'active','suspended','preserve control','fixture-operator','2026-10-11T15:50:28.458408Z');
CREATE TABLE ops_account_state (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id),
 state TEXT NOT NULL CHECK(state IN ('active','suspended')),
 version INTEGER NOT NULL CHECK(version > 0),
 reason TEXT NOT NULL, actor TEXT NOT NULL, changed_at TEXT NOT NULL
);
INSERT INTO "ops_account_state" VALUES('77b95d49-e1e4-40cb-a7f6-4a8ae691db1f','suspended',1,'preserve control','fixture-operator','2026-10-11T15:50:28.458408Z');
CREATE TABLE ops_billing_events (
 provider TEXT NOT NULL, event_id TEXT NOT NULL, digest TEXT NOT NULL,
 event_type TEXT NOT NULL, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 account_id TEXT NOT NULL, revision INTEGER NOT NULL, plan TEXT NOT NULL,
 outcome TEXT NOT NULL, received_at TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', reconciled_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(provider,event_id)
);
INSERT INTO "ops_billing_events" VALUES('stripe','evt_paid','0bb7530e70ff1f1f8bd5fd776bb793696bb62654cd8032c17b554bfd9b44228f','checkout.session.completed','sub_paid','cus_paid','c0dd4616-9df5-4a08-b141-2a84dcd527b2',0,'','reconciliation_required','2026-10-11T15:50:28.469009Z','','');
INSERT INTO "ops_billing_events" VALUES('provider-v1','evt_seq','e1f915344a5e3d3dacefd7b2b25cc384108e499a3b1d056dd1008b8c6222d1bf','subscription.updated','sub_seq','cus_seq','f12732ef-80a0-48dd-b844-6a01d58d2a62',1,'pro','applied','2026-10-11T15:50:28.476693Z','','');
INSERT INTO "ops_billing_events" VALUES('fixture','reconcile:19be547a-fa14-4c1d-9960-65bd61c40568','6359055379df0b022550db18056d37f4e57f4e3ca80ed41963d8e0c528829b0b','snapshot.reconciled','sub_fixture','cus_fixture','b6ce95f0-c2b1-44b9-a9d8-57e470b30250',1,'pro','reconciled','2026-10-11T15:50:28.486662Z','fixture-operator','');
CREATE TABLE ops_billing_mappings (
 provider TEXT NOT NULL, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 account_id TEXT NOT NULL REFERENCES accounts(id), version INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0, plan TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(provider,subscription_id), UNIQUE(provider,customer_id)
);
INSERT INTO "ops_billing_mappings" VALUES('stripe','sub_paid','cus_paid','c0dd4616-9df5-4a08-b141-2a84dcd527b2',0,0,'');
INSERT INTO "ops_billing_mappings" VALUES('provider-v1','sub_seq','cus_seq','f12732ef-80a0-48dd-b844-6a01d58d2a62',1,1,'pro');
INSERT INTO "ops_billing_mappings" VALUES('fixture','sub_fixture','cus_fixture','b6ce95f0-c2b1-44b9-a9d8-57e470b30250',1,1,'pro');
CREATE TABLE ops_reports (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL, category TEXT NOT NULL,
 endpoint TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
 created_at TEXT NOT NULL, changed_at TEXT NOT NULL, actor TEXT NOT NULL
);
CREATE TABLE reserved_subdomains (
		subdomain TEXT PRIMARY KEY,
		account_id TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
INSERT INTO "reserved_subdomains" VALUES('legacy-operator','77b95d49-e1e4-40cb-a7f6-4a8ae691db1f',1791733828);
INSERT INTO "reserved_subdomains" VALUES('legacy-manual','6a023117-f450-47e3-a714-1e9406c8597e',1791733828);
INSERT INTO "reserved_subdomains" VALUES('legacy-stripe-paid','c0dd4616-9df5-4a08-b141-2a84dcd527b2',1791733828);
INSERT INTO "reserved_subdomains" VALUES('legacy-sequenced','f12732ef-80a0-48dd-b844-6a01d58d2a62',1791733828);
INSERT INTO "reserved_subdomains" VALUES('legacy-fixture-reviewed','b6ce95f0-c2b1-44b9-a9d8-57e470b30250',1791733828);
INSERT INTO "reserved_subdomains" VALUES('legacy-merged','7cc444ea-65d4-4992-ac32-12932e834672',1791733828);
CREATE TABLE used_magic_tokens (
		jti TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX idx_accounts_primary_email ON accounts(primary_email);
CREATE INDEX idx_account_merges_account_id ON account_merges(account_id);
CREATE INDEX idx_account_emails_account_id ON account_emails(account_id);
CREATE INDEX idx_reserved_subdomains_account_id ON reserved_subdomains(account_id);
CREATE INDEX idx_used_magic_tokens_expires_at ON used_magic_tokens(expires_at);
CREATE INDEX ops_audit_account ON ops_account_audit(account_id,version);
CREATE INDEX ops_billing_account ON ops_billing_mappings(account_id);
CREATE INDEX ops_reports_account ON ops_reports(account_id);
COMMIT;
