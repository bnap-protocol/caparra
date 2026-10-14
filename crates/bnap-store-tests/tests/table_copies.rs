//! The SQLite and Postgres stores run `bnap_core::store::logic` over the
//! same in-transaction table; its two copies must never drift apart.

#[test]
fn both_backends_carry_the_same_transaction_table() {
    assert_eq!(
        include_str!("../../bnap-store-sqlite/src/table.rs"),
        include_str!("../../bnap-store-postgres/src/table.rs"),
        "edit crates/bnap-store-sqlite/src/table.rs and copy it to bnap-store-postgres"
    );
}
