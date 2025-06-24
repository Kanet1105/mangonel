fn main() {
    let worker_1 = std::thread::spawn(move || {
        let core_id = core_affinity::CoreId { id: 0 };
        let res = core_affinity::set_for_current(core_id);
        if res {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });

    let worker_2 = std::thread::spawn(move || {
        let core_id = core_affinity::CoreId { id: 0 };
        let res = core_affinity::set_for_current(core_id);
        if res {
            std::thread::sleep(std::time::Duration::from_secs(3));
        } else {
            println!("Unable to pin the worker thread to core ID: {}", 0);
        }
    });

    worker_1.join().unwrap();
    worker_2.join().unwrap();
}
