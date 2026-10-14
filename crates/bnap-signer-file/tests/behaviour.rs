//! The shared Signer behaviour suite (`testkit`) against the in-process
//! file signer, one check per test so a failure names its check.

use std::sync::Arc;

use bnap_core::test_support::block_on;
use bnap_plug::Signer;
use bnap_signer_file::FileSigner;
use bnap_signer_file::testkit::{self, KEY_FILE};

fn signer() -> Arc<dyn Signer> {
    Arc::new(FileSigner::from_toml(KEY_FILE).unwrap())
}

#[test]
fn signs_offers_and_acks_with_the_key_for_their_use() {
    block_on(testkit::signs_offers_and_acks_with_the_key_for_their_use(
        &signer(),
    ));
}

#[test]
fn refuses_foreign_messages() {
    block_on(testkit::refuses_foreign_messages(&signer()));
}

#[test]
fn blind_signatures_verify_with_the_cashu_crate() {
    block_on(testkit::blind_signatures_verify_with_the_cashu_crate(
        &signer(),
    ));
}

#[test]
fn notes_are_checked_against_their_secret() {
    block_on(testkit::notes_are_checked_against_their_secret(&signer()));
}

#[test]
fn refuses_outputs_over_the_cap() {
    block_on(testkit::refuses_outputs_over_the_cap(&signer()));
}

#[test]
fn refuses_zero_amounts_and_empty_batches() {
    block_on(testkit::refuses_zero_amounts_and_empty_batches(&signer()));
}

#[test]
fn refuses_outputs_it_must_not_sign() {
    block_on(testkit::refuses_outputs_it_must_not_sign(&signer()));
}

#[test]
fn change_goes_through_the_store_ledger() {
    block_on(testkit::change_goes_through_the_store_ledger(signer()));
}

#[test]
fn the_whole_suite_runs_on_one_signer() {
    block_on(testkit::run(signer()));
}
