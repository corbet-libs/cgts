use super::*;

#[tokio::test]
async fn a_real_poisoned_mutex_refuses_every_storage_operation() {
    let store = MemoryStore::new("garden").unwrap();
    let shared = store.clone();
    let failure = std::thread::spawn(move || {
        let _guard = shared.state.lock().unwrap();
        panic!("interrupt an actual memory-store writer");
    })
    .join();
    assert!(failure.is_err());
    assert_eq!(store.load("alice").await, Err(Error::Storage));
    assert_eq!(store.commit(None, None).await, Err(Error::Storage));
    assert_eq!(
        store.remove("alice", "cvch", "local").await,
        Err(Error::Storage)
    );
}
